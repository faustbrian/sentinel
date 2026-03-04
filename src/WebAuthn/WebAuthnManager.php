<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\WebAuthn;

use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\Events\WebAuthnCredentialRegistered;
use Cline\Sentinel\Events\WebAuthnCredentialRemoved;
use Cline\Sentinel\WebAuthn\Actions\ConfirmRegistrationAction;
use Cline\Sentinel\WebAuthn\Actions\GenerateAuthenticationOptionsAction;
use Cline\Sentinel\WebAuthn\Actions\GenerateRegistrationOptionsAction;
use Cline\Sentinel\WebAuthn\Actions\VerifyAuthenticationAction;
use Illuminate\Contracts\Auth\Authenticatable;

use function assert;
use function event;
use function is_string;

/**
 * Manages WebAuthn (passkeys & security keys) credential lifecycle and authentication.
 *
 * Provides a production-ready interface for WebAuthn credential registration and
 * verification using hardware security keys, biometric authenticators, or
 * platform authenticators (Windows Hello, Touch ID, Face ID).
 *
 * Supports both modes:
 * - **Passkeys**: Synced credentials stored in iCloud Keychain, Google Password Manager, etc.
 * - **Security Keys**: Device-bound credentials on YubiKey, Titan Key, etc.
 *
 * WebAuthn workflow:
 * 1. beginRegistration() - Generate challenge for credential creation
 * 2. Browser calls navigator.credentials.create() with options
 * 3. confirmRegistration() - Verify and store the new credential
 * 4. beginAuthentication() - Generate challenge for authentication
 * 5. Browser calls navigator.credentials.get() to sign challenge
 * 6. verify() - Validate the assertion signature
 *
 * ```php
 * // Register a new passkey
 * $options = Sentinel::webAuthn()->beginRegistration($user, asPasskey: true);
 * // ... send to browser, get response ...
 * $credential = Sentinel::webAuthn()->confirmRegistration($user, $credentialJson, $optionsJson, 'MacBook Touch ID', 'passkey');
 *
 * // Register a security key
 * $options = Sentinel::webAuthn()->beginRegistration($user, asPasskey: false);
 * // ... send to browser, get response ...
 * $credential = Sentinel::webAuthn()->confirmRegistration($user, $credentialJson, $optionsJson, 'YubiKey 5C', 'webauthn');
 *
 * // Authenticate
 * $options = Sentinel::webAuthn()->beginAuthentication($user);
 * // ... send to browser, get response ...
 * $verified = Sentinel::webAuthn()->verify($credentialJson, $optionsJson);
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @see    https://webauthn.guide/ for WebAuthn concepts
 * @see    https://github.com/web-auth/webauthn-framework for library details
 *
 * @psalm-immutable
 */
final readonly class WebAuthnManager
{
    /**
     * Create a new WebAuthn manager instance.
     *
     * @param GenerateRegistrationOptionsAction   $generateRegistrationOptions   Action for generating registration options
     * @param ConfirmRegistrationAction           $confirmRegistration           Action for confirming registration
     * @param GenerateAuthenticationOptionsAction $generateAuthenticationOptions Action for generating authentication options
     * @param VerifyAuthenticationAction          $verifyAuthentication          Action for verifying authentication
     */
    public function __construct(
        private GenerateRegistrationOptionsAction $generateRegistrationOptions,
        private ConfirmRegistrationAction $confirmRegistration,
        private GenerateAuthenticationOptionsAction $generateAuthenticationOptions,
        private VerifyAuthenticationAction $verifyAuthentication,
    ) {}

    /**
     * Begin WebAuthn credential registration.
     *
     * Generates PublicKeyCredentialCreationOptions that configure how the browser
     * should create a new WebAuthn credential. Store the returned JSON in session
     * as you'll need it to verify the attestation response.
     *
     * @param  Authenticatable $user      User registering the credential
     * @param  bool            $asPasskey True for passkeys (synced), false for security keys (device-bound)
     * @return string          JSON options to send to navigator.credentials.create()
     */
    public function beginRegistration(Authenticatable $user, bool $asPasskey = true): string
    {
        $result = $this->generateRegistrationOptions->execute($user, $asPasskey);

        assert(is_string($result), 'Registration options must be returned as JSON string');

        return $result;
    }

    /**
     * Confirm and store a WebAuthn credential after registration.
     *
     * Validates the browser's attestation response, verifies the cryptographic
     * signature, and stores the credential. The options JSON must be the exact
     * same options returned from beginRegistration().
     *
     * @param  Authenticatable       $user           User registering the credential
     * @param  string                $credentialJson PublicKeyCredential JSON from browser
     * @param  string                $optionsJson    Original options from beginRegistration()
     * @param  string                $hostname       Request hostname (e.g., 'example.com')
     * @param  string                $name           User-friendly name (e.g., "YubiKey 5C")
     * @param  string                $type           'passkey' or 'webauthn'
     * @return MultiFactorCredential Stored credential model
     */
    public function confirmRegistration(
        Authenticatable $user,
        string $credentialJson,
        string $optionsJson,
        string $hostname,
        string $name = 'Security Key',
        string $type = 'webauthn',
    ): MultiFactorCredential {
        $credential = $this->confirmRegistration->execute(
            user: $user,
            credentialJson: $credentialJson,
            optionsJson: $optionsJson,
            hostname: $hostname,
            name: $name,
            type: $type,
        );

        event(
            new WebAuthnCredentialRegistered($user, $credential->id, $name),
        );

        return $credential;
    }

    /**
     * Begin WebAuthn authentication challenge.
     *
     * Generates PublicKeyCredentialRequestOptions for authentication. Store the
     * returned JSON in session as you'll need it to verify the assertion response.
     *
     * @param  null|Authenticatable $user User to authenticate (null for discoverable credentials)
     * @return string               JSON options to send to navigator.credentials.get()
     */
    public function beginAuthentication(?Authenticatable $user = null): string
    {
        $result = $this->generateAuthenticationOptions->execute($user);

        assert(is_string($result), 'Authentication options must be returned as JSON string');

        return $result;
    }

    /**
     * Verify a WebAuthn authentication assertion.
     *
     * Validates the browser's assertion response, verifies the cryptographic
     * signature using the stored public key, and updates the credential's
     * signature counter. The options JSON must be the exact same options
     * returned from beginAuthentication().
     *
     * @param  string                $credentialJson PublicKeyCredential JSON from browser
     * @param  string                $optionsJson    Original options from beginAuthentication()
     * @param  string                $hostname       Request hostname (e.g., 'example.com')
     * @return MultiFactorCredential Verified credential (contains user relationship)
     */
    public function verify(
        string $credentialJson,
        string $optionsJson,
        string $hostname,
    ): MultiFactorCredential {
        return $this->verifyAuthentication->execute(
            credentialJson: $credentialJson,
            optionsJson: $optionsJson,
            hostname: $hostname,
        );
    }

    /**
     * Remove a WebAuthn credential.
     *
     * Permanently deletes the credential, preventing future use. The same
     * physical device can be re-registered by going through the registration
     * flow again.
     *
     * @param Authenticatable $user         User who owns the credential
     * @param string          $credentialId Credential UUID
     */
    public function remove(Authenticatable $user, string $credentialId): void
    {
        MultiFactorCredential::query()
            ->where('id', $credentialId)
            ->where('user_id', $user->getAuthIdentifier())
            ->whereIn('type', ['webauthn', 'passkey'])
            ->delete();

        event(
            new WebAuthnCredentialRemoved($user, $credentialId),
        );
    }
}
