<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\WebAuthn\Actions;

use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\Exceptions\InvalidWebAuthnAssertionException;
use Cline\Sentinel\WebAuthn\Support\WebAuthnSerializer;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use Throwable;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSource;

use function json_validate;
use function now;
use function throw_unless;

/**
 * Confirm and store a new WebAuthn credential after registration.
 *
 * Validates the browser's attestation response against the original challenge
 * and registration options, then stores the verified credential. This action
 * performs cryptographic verification to ensure the credential was created
 * by a legitimate authenticator and matches the expected challenge.
 *
 * Security validations performed:
 * - Challenge matches the one stored in session
 * - Origin matches the relying party
 * - Attestation signature is valid
 * - Credential ID is unique
 * - User verification occurred if required
 *
 * ```php
 * $action = new ConfirmRegistrationAction();
 *
 * $credential = $action->execute(
 *     user: $user,
 *     credentialJson: $request->input('credential'),
 *     optionsJson: session('webauthn.registration_options'),
 *     hostname: $request->getHost(),
 *     name: 'YubiKey 5C',
 *     type: 'webauthn'
 * );
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class ConfirmRegistrationAction
{
    /**
     * Execute the action to confirm and store a WebAuthn credential.
     *
     * Validates the attestation response from the browser, verifies all
     * security requirements, and stores the credential in the database.
     * The credential source contains the public key and metadata needed
     * for future authentication attempts.
     *
     * @param Authenticatable $user           User registering the credential
     * @param string          $credentialJson PublicKeyCredential JSON from browser
     * @param string          $optionsJson    Original PublicKeyCredentialCreationOptions from session
     * @param string          $hostname       Request hostname for origin validation
     * @param string          $name           User-provided name for the credential (e.g., "YubiKey 5C")
     * @param string          $type           Credential type: 'webauthn' or 'passkey'
     *
     * @throws InvalidWebAuthnAssertionException If validation fails
     * @return MultiFactorCredential             Stored credential model
     */
    public function execute(
        Authenticatable $user,
        string $credentialJson,
        string $optionsJson,
        string $hostname,
        string $name,
        string $type = 'webauthn',
    ): MultiFactorCredential {
        // Validate and verify the attestation response
        $credentialSource = $this->validateAndVerifyAttestation(
            credentialJson: $credentialJson,
            optionsJson: $optionsJson,
            hostname: $hostname,
        );

        // Store the verified credential
        return MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $user->getAuthIdentifier(),
            'type' => $type,
            'name' => $name,
            'secret' => WebAuthnSerializer::create()->toJson($credentialSource),
            'created_at' => now(),
        ]);
    }

    /**
     * Validate attestation response and extract credential source.
     *
     * Performs full cryptographic verification of the browser's attestation
     * response using the WebAuthn ceremony validation. This ensures the
     * credential was created by a legitimate authenticator.
     *
     * @param string $credentialJson PublicKeyCredential JSON from browser
     * @param string $optionsJson    Original registration options
     * @param string $hostname       Request hostname
     *
     * @throws InvalidWebAuthnAssertionException If any validation step fails
     * @return PublicKeyCredentialSource         Verified credential source with public key
     */
    private function validateAndVerifyAttestation(
        string $credentialJson,
        string $optionsJson,
        string $hostname,
    ): PublicKeyCredentialSource {
        // Deserialize registration options
        $options = $this->deserializeOptions($optionsJson);

        // Deserialize credential response
        $credential = $this->deserializeCredential($credentialJson);

        // Ensure response is attestation (not assertion)
        throw_unless($credential->response instanceof AuthenticatorAttestationResponse, InvalidWebAuthnAssertionException::class, 'Invalid credential response type. Expected attestation response.');

        // Validate using WebAuthn ceremony
        try {
            $ceremonyFactory = new CeremonyStepManagerFactory();
            $ceremonyStepping = $ceremonyFactory->creationCeremony();

            $validator = AuthenticatorAttestationResponseValidator::create($ceremonyStepping);

            return $validator->check(
                authenticatorAttestationResponse: $credential->response,
                publicKeyCredentialCreationOptions: $options,
                host: $hostname,
            );
        } catch (Throwable $throwable) {
            throw new InvalidWebAuthnAssertionException(message: 'WebAuthn attestation verification failed: '.$throwable->getMessage(), code: $throwable->getCode(), previous: $throwable);
        }
    }

    /**
     * Deserialize PublicKeyCredentialCreationOptions from JSON.
     *
     * @param string $optionsJson JSON string
     *
     * @throws InvalidWebAuthnAssertionException  If JSON is invalid
     * @return PublicKeyCredentialCreationOptions Deserialized options
     */
    private function deserializeOptions(string $optionsJson): PublicKeyCredentialCreationOptions
    {
        throw_unless(json_validate($optionsJson), InvalidWebAuthnAssertionException::class, 'Invalid registration options JSON.');

        try {
            $result = WebAuthnSerializer::create()->fromJson(
                $optionsJson,
                PublicKeyCredentialCreationOptions::class,
            );

            throw_unless($result instanceof PublicKeyCredentialCreationOptions, InvalidWebAuthnAssertionException::class, 'Deserialized result is not a PublicKeyCredentialCreationOptions instance.');

            return $result;
        } catch (Throwable $throwable) {
            throw new InvalidWebAuthnAssertionException(message: 'Failed to deserialize registration options: '.$throwable->getMessage(), code: $throwable->getCode(), previous: $throwable);
        }
    }

    /**
     * Deserialize PublicKeyCredential from JSON.
     *
     * @param string $credentialJson JSON string
     *
     * @throws InvalidWebAuthnAssertionException If JSON is invalid
     * @return PublicKeyCredential               Deserialized credential
     */
    private function deserializeCredential(string $credentialJson): PublicKeyCredential
    {
        throw_unless(json_validate($credentialJson), InvalidWebAuthnAssertionException::class, 'Invalid credential JSON.');

        try {
            $result = WebAuthnSerializer::create()->fromJson(
                $credentialJson,
                PublicKeyCredential::class,
            );

            throw_unless($result instanceof PublicKeyCredential, InvalidWebAuthnAssertionException::class, 'Deserialized result is not a PublicKeyCredential instance.');

            return $result;
        } catch (Throwable $throwable) {
            throw new InvalidWebAuthnAssertionException(message: 'Failed to deserialize credential: '.$throwable->getMessage(), code: $throwable->getCode(), previous: $throwable);
        }
    }
}
