<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel;

use Cline\Sentinel\Conductors\ForUserConductor;
use Cline\Sentinel\Events\MultiFactorChallengeCompleted;
use Cline\Sentinel\Events\MultiFactorChallengeInitiated;
use Cline\Sentinel\Events\SudoModeEnabled;
use Cline\Sentinel\RecoveryCodes\RecoveryCodeManager;
use Cline\Sentinel\Totp\TotpManager;
use Cline\Sentinel\WebAuthn\WebAuthnManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Date;

use function assert;
use function event;
use function now;

/**
 * Main Sentinel service for managing multi-factor authentication.
 *
 * This is the primary service class for the Sentinel package, providing a unified
 * interface for multi-factor authentication operations. It orchestrates multi-factor authentication
 * challenges, sudo mode, and provides access to specialized managers for TOTP,
 * WebAuthn, and recovery codes. The service maintains session-based state for
 * multi-factor authentication challenges and sudo mode confirmation.
 *
 * Key responsibilities:
 * - Managing multi-factor authentication challenge workflow (initiation, verification, completion)
 * - Controlling sudo mode activation and expiration
 * - Providing access to TOTP, WebAuthn, and recovery code managers
 * - Dispatching events for auditing and monitoring
 * - Managing session state for authentication flows
 *
 * ```php
 * // Access via facade
 * use Cline\Sentinel\Facades\Sentinel;
 *
 * // Check if user has multi-factor authentication enabled
 * if (Sentinel::for($user)->hasMultiFactorAuth()) {
 *     Sentinel::initiateMultiFactorChallenge($request, $user);
 * }
 *
 * // Access specialized managers
 * Sentinel::totp()->beginSetup($user);
 * Sentinel::webAuthn()->beginRegistration($user, 'YubiKey');
 * Sentinel::recoveryCodes()->generate($user);
 *
 * // Control sudo mode
 * Sentinel::enableSudoMode($request);
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Sentinel
{
    /**
     * Create a new Sentinel service instance.
     *
     * @param TotpManager         $totp          Manager for TOTP (Time-based One-Time Password)
     *                                           authentication, handling QR code generation and
     *                                           verification. Injected via container.
     * @param WebAuthnManager     $webAuthn      Manager for WebAuthn (hardware security key)
     *                                           authentication, handling registration and
     *                                           assertion verification. Injected via container.
     * @param RecoveryCodeManager $recoveryCodes Manager for recovery code generation,
     *                                           verification, and lifecycle management.
     *                                           Injected via container.
     * @param Repository          $config        Laravel configuration repository for accessing Sentinel
     *                                           settings (session keys, sudo duration, etc.).
     *                                           Injected via container.
     */
    public function __construct(
        private TotpManager $totp,
        private WebAuthnManager $webAuthn,
        private RecoveryCodeManager $recoveryCodes,
        private Repository $config,
    ) {}

    /**
     * Start a fluent interaction for a specific user.
     *
     * ```php
     * Sentinel::for($user)
     *     ->hasMultiFactorAuth();
     *
     * Sentinel::for($user)
     *     ->disableAllMfa();
     * ```
     *
     * @param  Authenticatable  $user The user to perform multi-factor authentication operations on
     * @return ForUserConductor Fluent conductor for user-specific operations
     */
    public function for(Authenticatable $user): ForUserConductor
    {
        /** @var User $user */
        return new ForUserConductor(
            $this->totp,
            $this->webAuthn,
            $this->recoveryCodes,
            $user,
        );
    }

    /**
     * Get the TOTP manager instance.
     *
     * Returns the manager for Time-based One-Time Password authentication,
     * which handles generating QR codes, verifying TOTP codes, and managing
     * TOTP credentials for users.
     *
     * @return TotpManager The TOTP manager for handling authenticator app-based multi-factor authentication
     */
    public function totp(): TotpManager
    {
        return $this->totp;
    }

    /**
     * Get the WebAuthn manager instance.
     *
     * Returns the manager for WebAuthn (hardware security key) authentication,
     * which handles credential registration, authentication assertions, and
     * managing WebAuthn credentials for users.
     *
     * @return WebAuthnManager The WebAuthn manager for handling security key-based multi-factor authentication
     */
    public function webAuthn(): WebAuthnManager
    {
        return $this->webAuthn;
    }

    /**
     * Get the recovery codes manager instance.
     *
     * Returns the manager for recovery code operations, which handles generating,
     * verifying, and managing single-use backup codes that users can use to
     * regain access if they lose their primary multi-factor authentication device.
     *
     * @return RecoveryCodeManager The recovery codes manager for handling backup authentication
     */
    public function recoveryCodes(): RecoveryCodeManager
    {
        return $this->recoveryCodes;
    }

    /**
     * Initiate an multi-factor authentication challenge for a user.
     *
     * Stores the user's identifier in the session to track the pending multi-factor authentication
     * challenge. This is typically called after initial password authentication
     * succeeds, before completing the login process. The user ID is stored
     * rather than the full user object for session efficiency. Dispatches
     * MfaChallengeInitiated event for auditing.
     *
     * @param Request         $request The current HTTP request with session access
     * @param Authenticatable $user    The user who needs to complete multi-factor authentication challenge
     */
    public function initiateMultiFactorChallenge(Request $request, Authenticatable $user): void
    {
        /** @var string $sessionKey */
        $sessionKey = $this->config->get('sentinel.session.multi_factor_challenge_user_id');

        // Store user ID in session to track pending challenge
        $request->session()->put(
            $sessionKey,
            $user->getAuthIdentifier(),
        );

        // Dispatch event for logging/monitoring
        event(
            new MultiFactorChallengeInitiated($user),
        );
    }

    /**
     * Get the user who is being challenged for multi-factor authentication.
     *
     * Retrieves the user model for the pending multi-factor authentication challenge by looking up
     * the user ID stored in session. Returns null if no challenge is pending
     * or if the user cannot be found (e.g., user was deleted after challenge
     * was initiated). The user model class is determined from the auth
     * configuration.
     *
     * @param  Request              $request The current HTTP request with session access
     * @return null|Authenticatable The user being challenged, or null if no challenge is pending
     */
    public function getChallengedUser(Request $request): ?Authenticatable
    {
        /** @var string $sessionKey */
        $sessionKey = $this->config->get('sentinel.session.multi_factor_challenge_user_id');

        $userId = $request->session()->get($sessionKey);

        if ($userId === null) {
            return null;
        }

        /** @var class-string<Authenticatable&Model> $userModel */
        $userModel = $this->config->get('auth.providers.users.model');

        $result = $userModel::query()->find($userId);

        // Eloquent find() with single ID returns Model|null, not Collection
        assert($result instanceof Authenticatable || $result === null);

        return $result;
    }

    /**
     * Mark multi-factor authentication challenge as completed in session.
     *
     * Stores the current timestamp in session to indicate successful multi-factor authentication
     * verification. This allows the user to access protected resources for
     * the remainder of their session without repeated multi-factor authentication challenges.
     * Dispatches MfaChallengeCompleted event for auditing if a challenged
     * user exists.
     *
     * @param Request $request The current HTTP request with session access
     */
    public function markMultiFactorComplete(Request $request): void
    {
        /** @var string $sessionKey */
        $sessionKey = $this->config->get('sentinel.session.multi_factor_completed_at');

        // Store completion timestamp in session
        $request->session()->put(
            $sessionKey,
            now()->timestamp,
        );

        // Dispatch event for logging/monitoring if user exists
        /** @var null|Authenticatable $user */
        $user = $this->getChallengedUser($request);

        if (!$user instanceof Authenticatable) {
            return;
        }

        event(
            new MultiFactorChallengeCompleted($user),
        );
    }

    /**
     * Check if multi-factor authentication challenge has been completed for this session.
     *
     * Determines whether the current session has successfully completed an
     * multi-factor authentication challenge. This is used by middleware to decide whether to allow
     * access to protected resources or redirect to the multi-factor authentication challenge page.
     * The check is session-based, so multi-factor authentication must be completed once per session.
     *
     * @param  Request $request The current HTTP request with session access
     * @return bool    True if multi-factor authentication challenge was completed this session, false otherwise
     */
    public function hasMultiFactorCompleted(Request $request): bool
    {
        /** @var string $sessionKey */
        $sessionKey = $this->config->get('sentinel.session.multi_factor_completed_at');

        return $request->session()->has($sessionKey);
    }

    /**
     * Clear multi-factor authentication challenge state from session.
     *
     * Removes the challenged user ID from the session, effectively canceling
     * any pending multi-factor authentication challenge. This is typically called after successful
     * login or when the user logs out. Note that this only clears the challenged
     * user ID, not the completion timestamp.
     *
     * @param Request $request The current HTTP request with session access
     */
    public function clearMultiFactorChallenge(Request $request): void
    {
        $request->session()->forget([
            $this->config->get('sentinel.session.multi_factor_challenge_user_id'),
        ]);
    }

    /**
     * Enable sudo mode for the current session.
     *
     * Activates sudo mode by storing the current timestamp in session. Sudo
     * mode provides an additional security layer for sensitive operations by
     * requiring recent password confirmation. Once enabled, sudo mode remains
     * active for a configured duration (default: 15 minutes). Dispatches
     * SudoModeEnabled event for auditing.
     *
     * @param Request $request The current HTTP request with session access
     */
    public function enableSudoMode(Request $request): void
    {
        /** @var string $sessionKey */
        $sessionKey = $this->config->get('sentinel.session.sudo_confirmed_at');

        // Store activation timestamp in session
        $request->session()->put(
            $sessionKey,
            now()->timestamp,
        );

        // Dispatch event for logging/monitoring if user is authenticated
        $user = $request->user();

        if ($user === null) {
            return;
        }

        /** @var Authenticatable $user */
        event(
            new SudoModeEnabled($user),
        );
    }

    /**
     * Check if sudo mode is currently active.
     *
     * Determines whether sudo mode is active by comparing the stored confirmation
     * timestamp against the configured duration. Sudo mode automatically expires
     * after the configured time period (default: 900 seconds / 15 minutes). This
     * time-based approach ensures sensitive operations require recent authentication
     * even within a long-lived session.
     *
     * @param  Request $request The current HTTP request with session access
     * @return bool    True if sudo mode is active and hasn't expired, false otherwise
     */
    public function inSudoMode(Request $request): bool
    {
        /** @var string $sessionKey */
        $sessionKey = $this->config->get('sentinel.session.sudo_confirmed_at');

        /** @var int $confirmedAt */
        $confirmedAt = $request->session()->get($sessionKey, 0);

        /** @var int $duration */
        $duration = $this->config->get('sentinel.sudo_mode.duration', 900);

        // Check if confirmation is within the valid time window
        return (int) now()->timestamp - $confirmedAt < $duration;
    }

    /**
     * Get the timestamp when sudo mode expires.
     *
     * Calculates and returns the exact time when sudo mode will expire based
     * on the confirmation timestamp and configured duration. Returns null if
     * sudo mode is not currently active. Useful for displaying countdown timers
     * or expiration warnings to users.
     *
     * @param  Request     $request The current HTTP request with session access
     * @return null|Carbon The expiration timestamp, or null if sudo mode is not active
     */
    public function sudoModeExpiresAt(Request $request): ?Carbon
    {
        /** @var string $sessionKey */
        $sessionKey = $this->config->get('sentinel.session.sudo_confirmed_at');

        /** @var null|int $confirmedAt */
        $confirmedAt = $request->session()->get($sessionKey);

        if ($confirmedAt === null) {
            return null;
        }

        /** @var int $duration */
        $duration = $this->config->get('sentinel.sudo_mode.duration', 900);

        /** @var int $confirmedAt */
        return Date::createFromTimestamp($confirmedAt)->addSeconds($duration);
    }

    /**
     * Disable all multi-factor authentication methods for a user.
     *
     * Removes all multi-factor authentication methods (TOTP, WebAuthn, recovery
     * codes) for the specified user. This is a convenience method that delegates
     * to the ForUserConductor. Typically used when a user chooses to disable multi-factor authentication
     * or when removing multi-factor authentication as part of account cleanup.
     *
     * @param Authenticatable $user The user whose multi-factor authentication methods should be disabled
     */
    public function disableAllMfa(Authenticatable $user): void
    {
        $this->for($user)->disableAllMfa();
    }
}
