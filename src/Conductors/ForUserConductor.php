<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\Conductors;

use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\RecoveryCodes\RecoveryCodeManager;
use Cline\Sentinel\Totp\TotpManager;
use Cline\Sentinel\WebAuthn\WebAuthnManager;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Foundation\Auth\User;

/**
 * User-scoped multi-factor authentication operations conductor providing a fluent interface for multi-factor authentication management.
 *
 * This conductor provides a chainable, user-specific API for checking multi-factor authentication status,
 * retrieving credentials, and managing multi-factor authentication methods. It acts as a facade over the
 * underlying TOTP, WebAuthn, and recovery code managers, providing a consistent
 * interface for all user-scoped multi-factor authentication operations.
 *
 * The conductor is immutable and thread-safe, designed to be created per-request
 * via the Sentinel facade's `for()` method. All operations are read-heavy with
 * the exception of `disableAllMfa()` which coordinates deletions across managers.
 *
 * ```php
 * // Check multi-factor authentication status
 * $hasAnyMfa = Sentinel::for($user)->hasMultiFactorAuth();
 * $hasTotp = Sentinel::for($user)->hasTotpEnabled();
 * $hasWebAuthn = Sentinel::for($user)->hasWebAuthnEnabled();
 *
 * // Retrieve credentials
 * $totpCredential = Sentinel::for($user)->getTotpCredential();
 * $webAuthnCredentials = Sentinel::for($user)->getWebAuthnCredentials();
 *
 * // Check recovery codes
 * $hasRecovery = Sentinel::for($user)->hasRecoveryCodes();
 * $remaining = Sentinel::for($user)->remainingRecoveryCodes();
 *
 * // Disable all multi-factor authentication
 * Sentinel::for($user)->disableAllMfa();
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class ForUserConductor
{
    /**
     * Create a new user-scoped multi-factor authentication conductor instance.
     *
     * @param TotpManager         $totp          Manager for TOTP credential operations including
     *                                           verification, enabling, and disabling TOTP authentication.
     * @param WebAuthnManager     $webAuthn      Manager for WebAuthn credential operations including
     *                                           registration, verification, and removal of hardware keys.
     * @param RecoveryCodeManager $recoveryCodes Manager for recovery code operations including
     *                                           generation, validation, and tracking usage of
     *                                           emergency access codes.
     * @param User                $user          The authenticated user instance to perform multi-factor authentication operations on.
     *                                           Must use the HasMultiFactorAuthentication trait to provide
     *                                           the necessary Eloquent relationships for credentials and codes.
     */
    public function __construct(
        private TotpManager $totp,
        private WebAuthnManager $webAuthn,
        private RecoveryCodeManager $recoveryCodes,
        private User $user,
    ) {}

    /**
     * Determine if the user has any multi-factor authentication method enabled.
     *
     * Performs an existence check across all credential types (TOTP and WebAuthn)
     * without loading credential records. This is the most efficient way to check
     * if a user has multi-factor authentication protection enabled.
     *
     * @return bool True if user has at least one multi-factor authentication credential of any type
     */
    public function hasMultiFactorAuth(): bool
    {
        /** @var \Illuminate\Database\Eloquent\Relations\HasMany<MultiFactorCredential, User> $credentials */
        /**
         * multiFactorCredentials() provided by HasMultiFactorAuthentication trait
         * @phpstan-ignore-next-line method.notFound
         */
        $credentials = $this->user->multiFactorCredentials();

        return $credentials->exists();
    }

    /**
     * Determine if the user has TOTP authentication enabled.
     *
     * Checks for the existence of a TOTP credential without loading the sensitive
     * secret data. TOTP (Time-based One-Time Password) uses apps like Google
     * Authenticator or Authy to generate time-sensitive codes.
     *
     * @return bool True if user has an active TOTP credential
     */
    public function hasTotpEnabled(): bool
    {
        /** @var \Illuminate\Database\Eloquent\Relations\HasMany<MultiFactorCredential, User> $credentials */
        /**
         * multiFactorCredentials() provided by HasMultiFactorAuthentication trait
         * @phpstan-ignore-next-line method.notFound
         */
        $credentials = $this->user->multiFactorCredentials();

        return $credentials->where('type', 'totp')->exists();
    }

    /**
     * Determine if the user has WebAuthn authentication enabled.
     *
     * Checks for the existence of at least one WebAuthn credential. WebAuthn enables
     * hardware-based authentication using security keys (like YubiKey) or platform
     * authenticators (like Touch ID or Windows Hello).
     *
     * @return bool True if user has at least one registered WebAuthn credential
     */
    public function hasWebAuthnEnabled(): bool
    {
        /** @var \Illuminate\Database\Eloquent\Relations\HasMany<MultiFactorCredential, User> $credentials */
        /**
         * multiFactorCredentials() provided by HasMultiFactorAuthentication trait
         * @phpstan-ignore-next-line method.notFound
         */
        $credentials = $this->user->multiFactorCredentials();

        return $credentials->where('type', 'webauthn')->exists();
    }

    /**
     * Determine if the user has unused recovery codes available.
     *
     * Recovery codes provide emergency account access when primary multi-factor authentication methods
     * are unavailable (e.g., lost phone or hardware key). This checks for codes
     * that haven't been consumed (used_at is null).
     *
     * @return bool True if user has at least one unused recovery code
     */
    public function hasRecoveryCodes(): bool
    {
        /** @var \Illuminate\Database\Eloquent\Relations\HasMany<\Cline\Sentinel\Database\Models\MultiFactorRecoveryCode, User> $recoveryCodes */
        /**
         * multiFactorRecoveryCodes() provided by HasMultiFactorAuthentication trait
         * @phpstan-ignore-next-line method.notFound
         */
        $recoveryCodes = $this->user->multiFactorRecoveryCodes();

        return $recoveryCodes->whereNull('used_at')->exists();
    }

    /**
     * Retrieve the user's TOTP credential.
     *
     * Returns the TOTP credential containing the encrypted secret and metadata.
     * Users can only have one TOTP credential at a time. The secret is automatically
     * decrypted by Laravel's encrypted casting when accessed.
     *
     * @return null|MultiFactorCredential The TOTP credential if enabled, null otherwise
     */
    public function getTotpCredential(): ?MultiFactorCredential
    {
        /** @var \Illuminate\Database\Eloquent\Relations\HasMany<MultiFactorCredential, User> $credentials */
        /**
         * multiFactorCredentials() provided by HasMultiFactorAuthentication trait
         * @phpstan-ignore-next-line method.notFound
         */
        $credentials = $this->user->multiFactorCredentials();

        return $credentials->where('type', 'totp')->first();
    }

    /**
     * Retrieve all WebAuthn credentials registered for the user.
     *
     * Returns a collection of WebAuthn credentials, each representing a registered
     * hardware security key or platform authenticator. Users can register multiple
     * WebAuthn credentials for redundancy and convenience.
     *
     * @return Collection<int, MultiFactorCredential> Collection of WebAuthn credentials, empty if none registered
     */
    public function getWebAuthnCredentials(): Collection
    {
        /** @var \Illuminate\Database\Eloquent\Relations\HasMany<MultiFactorCredential, User> $credentials */
        /**
         * multiFactorCredentials() provided by HasMultiFactorAuthentication trait
         * @phpstan-ignore-next-line method.notFound
         */
        $credentials = $this->user->multiFactorCredentials();

        return $credentials->where('type', 'webauthn')->get();
    }

    /**
     * Get the count of unused recovery codes available to the user.
     *
     * Returns the number of recovery codes that haven't been consumed yet. This is
     * useful for UI feedback to warn users when they're running low on backup codes.
     * Typically, 8-10 codes are generated when multi-factor authentication is enabled.
     *
     * @return int Number of unused recovery codes (0 if none available)
     */
    public function remainingRecoveryCodes(): int
    {
        return $this->recoveryCodes->remaining($this->user);
    }

    /**
     * Disable and remove all multi-factor authentication methods for the user.
     *
     * This is a destructive operation that removes all multi-factor authentication protection from the account:
     * - Deletes the TOTP credential and secret
     * - Invalidates all recovery codes
     * - Removes all registered WebAuthn credentials
     *
     * Use this when a user explicitly disables multi-factor authentication or during account cleanup. This
     * operation cannot be undone and the user will need to re-enroll in multi-factor authentication if they
     * want to re-enable it.
     */
    public function disableAllMfa(): void
    {
        // Remove TOTP credential and secret
        $this->totp->disable($this->user);

        // Mark all recovery codes as invalid
        $this->recoveryCodes->invalidate($this->user);

        /** @var \Illuminate\Database\Eloquent\Relations\HasMany<MultiFactorCredential, User> $credentials */
        /**
         * multiFactorCredentials() provided by HasMultiFactorAuthentication trait
         * @phpstan-ignore-next-line method.notFound
         */
        $credentials = $this->user->multiFactorCredentials();

        /** @var Collection<int, MultiFactorCredential> $webAuthnCredentials */
        $webAuthnCredentials = $credentials->where('type', 'webauthn')->get();

        // Remove each WebAuthn credential individually
        foreach ($webAuthnCredentials as $credential) {
            $this->webAuthn->remove($this->user, (string) $credential->id);
        }
    }
}
