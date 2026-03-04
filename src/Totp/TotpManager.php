<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\Totp;

use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\Events\MultiFactorChallengeFailed;
use Cline\Sentinel\Events\TotpDisabled;
use Cline\Sentinel\Events\TotpEnabled;
use Cline\Sentinel\Exceptions\TotpSetupNotInitializedException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Str;

use function decrypt;
use function encrypt;
use function event;
use function now;

/**
 * Manages TOTP (Time-based One-Time Password) authentication lifecycle.
 *
 * Orchestrates the complete TOTP workflow including setup initialization,
 * verification, confirmation, and credential management. Integrates with
 * session storage for temporary setup state and database storage for
 * confirmed credentials.
 *
 * Typical workflow:
 * 1. beginSetup() - Generate secret and QR code for authenticator app
 * 2. User scans QR code in their authenticator app
 * 3. confirmSetup() - Verify the first code to activate TOTP
 * 4. verify() - Validate codes during multi-factor authentication challenges
 * 5. disable() - Remove TOTP from user's account
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class TotpManager
{
    /**
     * Create a new TOTP manager instance.
     *
     * @param TotpVerifier $verifier Service that handles cryptographic TOTP operations
     *                               including secret generation and code verification
     *                               using the Google2FA library implementation.
     * @param Repository   $config   Laravel configuration repository providing access
     *                               to TOTP settings including issuer name, window size,
     *                               and session key configuration values.
     * @param Session      $session  Laravel session manager used for temporary storage
     *                               of encrypted TOTP secrets during the setup process
     *                               before confirmation and database persistence.
     */
    public function __construct(
        private TotpVerifier $verifier,
        private Repository $config,
        private Session $session,
    ) {}

    /**
     * Initiate TOTP setup by generating a secret and provisioning data.
     *
     * Generates a cryptographically secure TOTP secret, encrypts it, and
     * stores it in the session for later confirmation. Returns a TotpSetup
     * object containing QR code data and provisioning URI for authenticator apps.
     *
     * The secret remains in session until confirmSetup() is called or
     * cancelSetup() clears it. This prevents premature activation.
     *
     * @param Authenticatable $user The user initiating TOTP setup, used to generate
     *                              account identifier for authenticator apps.
     *
     * @return TotpSetup Value object containing secret, QR code, and provisioning
     *                   URI for configuring authenticator applications.
     */
    public function beginSetup(Authenticatable $user): TotpSetup
    {
        // Generate a cryptographically secure random secret for TOTP
        $secret = $this->verifier->generateSecret();

        // Encrypt and store the secret in session until confirmation
        /** @var string $sessionKey */
        $sessionKey = $this->config->get('sentinel.session.totp_setup_secret');
        $this->session->put($sessionKey, encrypt($secret));

        // Build provisioning data for authenticator apps
        /** @var string $issuer */
        $issuer = $this->config->get('sentinel.totp.issuer', 'Laravel');

        /** @var null|string $userEmail */
        $userEmail = $user->email ?? null;

        /** @var int|string $userId */
        $userId = $user->getAuthIdentifier();

        // Prefer email for account name, fallback to user ID
        $accountName = $userEmail ?? (string) $userId;

        return new TotpSetup($secret, $issuer, $accountName);
    }

    /**
     * Confirm and activate TOTP by verifying a code from the authenticator app.
     *
     * Validates the provided code against the secret stored in session during
     * beginSetup(). If valid, creates a permanent MultiFactorCredential record and
     * clears the session state. If invalid, fires a failure event.
     *
     * This two-step process (begin + confirm) ensures users successfully
     * configured their authenticator app before activation.
     *
     * @param Authenticatable $user The user confirming TOTP setup.
     * @param string          $code The 6-digit verification code from their
     *                              authenticator application.
     *
     * @throws TotpSetupNotInitializedException If beginSetup() was not called
     *                                          or session expired.
     * @return bool                             True if code is valid and TOTP was activated, false if
     *                                          code verification failed.
     */
    public function confirmSetup(Authenticatable $user, string $code): bool
    {
        // Retrieve encrypted secret from session
        /** @var string $sessionKey */
        $sessionKey = $this->config->get('sentinel.session.totp_setup_secret');
        $encryptedSecret = $this->session->get($sessionKey);

        // Ensure setup was initiated before attempting confirmation
        if ($encryptedSecret === null) {
            throw TotpSetupNotInitializedException::create();
        }

        /** @var string $encryptedValue */
        $encryptedValue = $encryptedSecret;

        /** @var string $secret */
        $secret = decrypt($encryptedValue);

        // Verify the code matches the secret
        if (!$this->verifier->verify($secret, $code)) {
            event(
                new MultiFactorChallengeFailed($user, 'totp'),
            );

            return false;
        }

        // Code is valid - persist the credential
        MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $user->getAuthIdentifier(),
            'type' => 'totp',
            'name' => 'Authenticator App',
            'secret' => $secret,
            'created_at' => now(),
        ]);

        // Clear setup state from session
        $this->session->forget($sessionKey);

        // Notify listeners that TOTP is now active
        event(
            new TotpEnabled($user),
        );

        return true;
    }

    /**
     * Cancel TOTP setup and clear pending session state.
     *
     * Removes the encrypted secret from session without activating TOTP.
     * Useful when users abandon setup or navigate away during the process.
     */
    public function cancelSetup(): void
    {
        /** @var string $sessionKey */
        $sessionKey = $this->config->get('sentinel.session.totp_setup_secret');
        $this->session->forget($sessionKey);
    }

    /**
     * Verify a TOTP code during an multi-factor authentication authentication challenge.
     *
     * Looks up the user's active TOTP credential and validates the provided
     * code against their stored secret. Updates the last_used_at timestamp
     * on successful verification. Fires failure events for invalid codes.
     *
     * @param Authenticatable $user The user attempting to authenticate.
     * @param string          $code The 6-digit code from their authenticator app.
     *
     * @return bool True if the code is valid, false otherwise or if no TOTP
     *              credential exists for the user.
     */
    public function verify(Authenticatable $user, string $code): bool
    {
        // Retrieve the user's TOTP credential
        /** @var null|MultiFactorCredential $credential */
        $credential = MultiFactorCredential::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->where('type', 'totp')
            ->first();

        // User has no TOTP configured
        if ($credential === null) {
            return false;
        }

        // Verify the code against the stored secret
        $valid = $this->verifier->verify($credential->secret, $code);

        if ($valid) {
            // Update usage tracking for security monitoring
            $credential->update(['last_used_at' => now()]);
        } else {
            // Log failed attempt for security auditing
            event(
                new MultiFactorChallengeFailed($user, 'totp'),
            );
        }

        return $valid;
    }

    /**
     * Disable TOTP authentication for a user.
     *
     * Permanently removes the user's TOTP credential from the database.
     * After calling this method, the user will no longer be challenged
     * for TOTP codes during authentication.
     *
     * @param Authenticatable $user The user whose TOTP should be disabled.
     */
    public function disable(Authenticatable $user): void
    {
        MultiFactorCredential::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->where('type', 'totp')
            ->delete();

        event(
            new TotpDisabled($user),
        );
    }
}
