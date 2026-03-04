<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\WebAuthn\Actions;

use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\WebAuthn\Support\WebAuthnSerializer;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

use function config;

/**
 * Generate WebAuthn authentication options for credential verification.
 *
 * Creates PublicKeyCredentialRequestOptions that configure how the browser
 * should authenticate using an existing WebAuthn credential. This action
 * handles challenge generation, allowed credential filtering, and relying
 * party configuration.
 *
 * Supports two modes:
 * - **User-specific**: Only allows credentials registered by a specific user
 * - **Discoverable**: Allows any credential (for passkey-only login flows)
 *
 * ```php
 * $action = new GenerateAuthenticationOptionsAction();
 *
 * // Generate options for specific user (MFA flow)
 * $options = $action->execute($user);
 *
 * // Generate options for discoverable credentials (passkey-first login)
 * $options = $action->execute();
 *
 * // Get as JSON for JavaScript
 * $json = $action->execute($user, asJson: true);
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class GenerateAuthenticationOptionsAction
{
    /**
     * Execute the action to generate authentication options.
     *
     * Creates PublicKeyCredentialRequestOptions with appropriate settings
     * for WebAuthn authentication. When a user is provided, only their
     * credentials are allowed. Without a user, any credential can be used
     * (discoverable credential flow for passkey-first login).
     *
     * @param  null|Authenticatable                     $user   User to authenticate (null for discoverable)
     * @param  bool                                     $asJson Whether to return JSON string or object
     * @return PublicKeyCredentialRequestOptions|string Authentication options object or JSON string
     */
    public function execute(
        ?Authenticatable $user = null,
        bool $asJson = true,
    ): PublicKeyCredentialRequestOptions|string {
        /** @var null|string $rpId */
        $rpId = config('sentinel.webauthn.relying_party.id');

        $options = new PublicKeyCredentialRequestOptions(
            challenge: $this->generateChallenge(),
            rpId: $rpId,
            allowCredentials: $user instanceof Authenticatable ? $this->buildAllowedCredentials($user) : [],
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
        );

        if ($asJson) {
            return WebAuthnSerializer::create()->toJson($options);
        }

        return $options;
    }

    /**
     * Generate cryptographically random challenge.
     *
     * The challenge prevents replay attacks and must be stored in session
     * for verification during authentication. Minimum 16 bytes recommended
     * by WebAuthn spec.
     *
     * @return string Random challenge string (32 characters)
     */
    private function generateChallenge(): string
    {
        return Str::random(32);
    }

    /**
     * Build list of allowed credentials for the user.
     *
     * Retrieves all WebAuthn/passkey credentials registered by the user
     * and converts them to PublicKeyCredentialDescriptor objects that
     * tell the browser which credentials are allowed for authentication.
     *
     * @param  Authenticatable                           $user User to get credentials for
     * @return array<int, PublicKeyCredentialDescriptor> List of allowed credential descriptors
     */
    private function buildAllowedCredentials(Authenticatable $user): array
    {
        /** @var Collection<int, MultiFactorCredential> $credentials */
        $credentials = MultiFactorCredential::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->whereIn('type', ['webauthn', 'passkey'])
            ->get();

        return $credentials
            ->map(function (MultiFactorCredential $credential): PublicKeyCredentialDescriptor {
                /** @var PublicKeyCredentialSource $source */
                $source = WebAuthnSerializer::create()->fromJson(
                    $credential->secret,
                    PublicKeyCredentialSource::class,
                );

                return new PublicKeyCredentialDescriptor(
                    type: PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    id: $source->publicKeyCredentialId,
                );
            })
            ->all();
    }
}
