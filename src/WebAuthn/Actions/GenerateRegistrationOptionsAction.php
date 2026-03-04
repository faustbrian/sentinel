<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\WebAuthn\Actions;

use Cline\Sentinel\WebAuthn\Support\WebAuthnSerializer;
use Cose\Algorithms;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

use function config;

/**
 * Generate WebAuthn registration options for credential creation.
 *
 * Creates PublicKeyCredentialCreationOptions that configure how the browser
 * should create a new WebAuthn credential. This action handles challenge
 * generation, relying party configuration, user entity creation, and
 * authenticator selection criteria.
 *
 * Supports both passkey (synced) and security key (device-bound) modes
 * through the residentKey parameter. Passkeys require resident key support
 * for cross-device sync, while security keys can be device-bound.
 *
 * ```php
 * $action = new GenerateRegistrationOptionsAction();
 *
 * // Generate passkey options (default - synced across devices)
 * $options = $action->execute($user, asPasskey: true);
 *
 * // Generate security key options (device-bound)
 * $options = $action->execute($user, asPasskey: false);
 *
 * // Get as JSON for JavaScript
 * $json = $action->execute($user, asJson: true);
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class GenerateRegistrationOptionsAction
{
    /**
     * Execute the action to generate registration options.
     *
     * Creates PublicKeyCredentialCreationOptions with appropriate settings
     * for either passkey (synced) or security key (device-bound) registration.
     * The challenge should be stored in session for verification during
     * credential confirmation.
     *
     * @param  Authenticatable                           $user      User registering the credential
     * @param  bool                                      $asPasskey True for passkeys (synced), false for security keys (device-bound)
     * @param  bool                                      $asJson    Whether to return JSON string or object
     * @return PublicKeyCredentialCreationOptions|string Registration options object or JSON string
     */
    public function execute(
        Authenticatable $user,
        bool $asPasskey = true,
        bool $asJson = true,
    ): PublicKeyCredentialCreationOptions|string {
        $options = new PublicKeyCredentialCreationOptions(
            rp: $this->buildRelyingPartyEntity(),
            user: $this->buildUserEntity($user),
            challenge: $this->generateChallenge(),
            pubKeyCredParams: $this->supportedAlgorithms(),
            authenticatorSelection: $this->buildAuthenticatorSelection($asPasskey),
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        );

        if ($asJson) {
            return WebAuthnSerializer::create()->toJson($options);
        }

        return $options;
    }

    /**
     * Build relying party entity from configuration.
     *
     * The relying party represents your application in the WebAuthn protocol.
     * The ID must match the domain where registration occurs (e.g., "example.com").
     *
     * @return PublicKeyCredentialRpEntity Relying party entity with name and ID
     */
    private function buildRelyingPartyEntity(): PublicKeyCredentialRpEntity
    {
        /** @var string $name */
        $name = config('sentinel.webauthn.relying_party.name');

        /** @var null|string $id */
        $id = config('sentinel.webauthn.relying_party.id');

        return new PublicKeyCredentialRpEntity(
            name: $name,
            id: $id,
        );
    }

    /**
     * Build user entity from authenticatable.
     *
     * The user entity identifies who the credential belongs to. The ID should
     * be a unique, immutable identifier (not email, as it may change). The
     * name and displayName are shown during authentication prompts.
     *
     * @param  Authenticatable               $user User to create entity for
     * @return PublicKeyCredentialUserEntity User entity with ID, name, and display name
     */
    private function buildUserEntity(Authenticatable $user): PublicKeyCredentialUserEntity
    {
        /** @var int|string $userId */
        $userId = $user->getAuthIdentifier();

        /** @var null|string $userEmail */
        $userEmail = $user->email ?? null;

        /** @var null|string $userName */
        $userName = $user->name ?? null;

        return new PublicKeyCredentialUserEntity(
            name: $userEmail ?? (string) $userId,
            id: (string) $userId,
            displayName: $userName ?? $userEmail ?? 'User',
        );
    }

    /**
     * Generate cryptographically random challenge.
     *
     * The challenge prevents replay attacks and must be stored in session
     * for verification during confirmRegistration(). Minimum 16 bytes
     * recommended by WebAuthn spec.
     *
     * @return string Random challenge string (32 characters)
     */
    private function generateChallenge(): string
    {
        return Str::random(32);
    }

    /**
     * Define supported cryptographic algorithms.
     *
     * Specifies which public key algorithms the authenticator can use.
     * ES256 (ECDSA) is preferred for its security and efficiency.
     * RS256 (RSA) provided as fallback for older authenticators.
     *
     * @return array<int, PublicKeyCredentialParameters> Supported algorithm list
     */
    private function supportedAlgorithms(): array
    {
        return [
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ES256),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_RS256),
        ];
    }

    /**
     * Build authenticator selection criteria.
     *
     * Determines whether to create a passkey (synced credential) or security
     * key (device-bound credential). Passkeys require resident key support
     * for cross-device sync via iCloud Keychain, Google Password Manager, etc.
     *
     * @param  bool                           $asPasskey True for passkeys (synced), false for security keys
     * @return AuthenticatorSelectionCriteria Selection criteria for the authenticator
     */
    private function buildAuthenticatorSelection(bool $asPasskey): AuthenticatorSelectionCriteria
    {
        return new AuthenticatorSelectionCriteria(
            authenticatorAttachment: null,
            userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            // Allow both platform (Touch ID) and cross-platform (YubiKey)
            residentKey: $asPasskey
                ? AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED
                : AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_DISCOURAGED,
        );
    }
}
