<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\WebAuthn\Actions;

use Cline\Sentinel\Contracts\AuthenticatorAssertionValidator;
use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\Exceptions\InvalidWebAuthnAssertionException;
use Cline\Sentinel\WebAuthn\Support\WebAuthnSerializer;
use Illuminate\Support\Collection;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

use function assert;
use function json_validate;
use function mb_convert_encoding;
use function now;
use function throw_if;
use function throw_unless;

/**
 * Verify a WebAuthn authentication assertion.
 *
 * Validates the browser's assertion response against the original challenge
 * and updates the credential's signature counter. This action performs
 * cryptographic verification to ensure the assertion was created by the
 * legitimate authenticator and prevents replay attacks.
 *
 * Security validations performed:
 * - Challenge matches the one stored in session
 * - Origin matches the relying party
 * - Assertion signature is valid using the credential's public key
 * - Signature counter is incremented (prevents cloning attacks)
 * - User verification occurred if required
 *
 * ```php
 * $action = new VerifyAuthenticationAction();
 *
 * $credential = $action->execute(
 *     credentialJson: $request->input('credential'),
 *     optionsJson: session('webauthn.authentication_options'),
 *     hostname: $request->getHost()
 * );
 *
 * // Credential verified - user authenticated
 * Auth::login($credential->user);
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class VerifyAuthenticationAction
{
    /**
     * Create a new verify authentication action instance.
     *
     * @param AuthenticatorAssertionValidator $validator Assertion validator
     */
    public function __construct(
        private AuthenticatorAssertionValidator $validator,
    ) {}

    /**
     * Execute the action to verify a WebAuthn authentication.
     *
     * Validates the assertion response from the browser, verifies all
     * security requirements, updates the credential's signature counter,
     * and returns the verified credential.
     *
     * @param string $credentialJson PublicKeyCredential JSON from browser
     * @param string $optionsJson    Original PublicKeyCredentialRequestOptions from session
     * @param string $hostname       Request hostname for origin validation
     *
     * @throws InvalidWebAuthnAssertionException If validation fails
     * @return MultiFactorCredential             Verified credential (contains user relationship)
     */
    public function execute(
        string $credentialJson,
        string $optionsJson,
        string $hostname,
    ): MultiFactorCredential {
        // Deserialize and validate credential response
        $credential = $this->deserializeCredential($credentialJson);

        // Find the matching stored credential
        $storedCredential = $this->findStoredCredential($credential);

        // Verify the assertion
        $verifiedSource = $this->validateAndVerifyAssertion(
            credential: $credential,
            optionsJson: $optionsJson,
            storedCredential: $storedCredential,
            hostname: $hostname,
        );

        // Update credential with new counter and usage timestamp
        $this->updateCredential($storedCredential, $verifiedSource);

        return $storedCredential;
    }

    /**
     * Validate assertion response and verify signature.
     *
     * Performs full cryptographic verification of the browser's assertion
     * response using the WebAuthn ceremony validation. This ensures the
     * assertion was created by the legitimate authenticator.
     *
     * @param PublicKeyCredential   $credential       Credential from browser
     * @param string                $optionsJson      Original request options
     * @param MultiFactorCredential $storedCredential Stored credential with public key
     * @param string                $hostname         Request hostname
     *
     * @throws InvalidWebAuthnAssertionException If validation fails
     * @return PublicKeyCredentialSource         Updated credential source with new counter
     */
    private function validateAndVerifyAssertion(
        PublicKeyCredential $credential,
        string $optionsJson,
        MultiFactorCredential $storedCredential,
        string $hostname,
    ): PublicKeyCredentialSource {
        // Deserialize request options
        $options = $this->deserializeOptions($optionsJson);

        // Deserialize stored credential source
        /** @var PublicKeyCredentialSource $credentialSource */
        $credentialSource = WebAuthnSerializer::create()->fromJson(
            $storedCredential->secret,
            PublicKeyCredentialSource::class,
        );

        // Type guard: response is verified as AuthenticatorAssertionResponse in deserializeCredential
        $response = $credential->response;
        assert($response instanceof AuthenticatorAssertionResponse);

        // Validate using WebAuthn ceremony
        try {
            return $this->validator->check(
                publicKeyCredentialSource: $credentialSource,
                authenticatorAssertionResponse: $response,
                publicKeyCredentialRequestOptions: $options,
                host: $hostname,
                userHandle: null,
            );
        } catch (Throwable $throwable) {
            throw new InvalidWebAuthnAssertionException(message: 'WebAuthn assertion verification failed: '.$throwable->getMessage(), code: $throwable->getCode(), previous: $throwable);
        }
    }

    /**
     * Deserialize PublicKeyCredential from JSON.
     *
     * @param string $credentialJson JSON string
     *
     * @throws InvalidWebAuthnAssertionException If JSON is invalid or response type is wrong
     * @return PublicKeyCredential               Deserialized credential
     */
    private function deserializeCredential(string $credentialJson): PublicKeyCredential
    {
        throw_unless(json_validate($credentialJson), InvalidWebAuthnAssertionException::class, 'Invalid credential JSON.');

        /** @var PublicKeyCredential $credential */
        $credential = WebAuthnSerializer::create()->fromJson(
            $credentialJson,
            PublicKeyCredential::class,
        );

        throw_unless($credential->response instanceof AuthenticatorAssertionResponse, InvalidWebAuthnAssertionException::class, 'Invalid credential response type. Expected assertion response.');

        return $credential;
    }

    /**
     * Find stored credential matching the assertion.
     *
     * Searches for a credential with matching credential ID. The rawId from
     * the browser must match a stored credential's ID.
     *
     * @param PublicKeyCredential $credential Credential from browser
     *
     * @throws InvalidWebAuthnAssertionException If credential not found
     * @return MultiFactorCredential             Matching stored credential
     */
    private function findStoredCredential(PublicKeyCredential $credential): MultiFactorCredential
    {
        // Extract credential ID from the stored credential source to match against
        // We need to deserialize all WebAuthn credentials and compare IDs
        $credentialId = mb_convert_encoding($credential->rawId, 'UTF-8');

        /** @var Collection<int, MultiFactorCredential> $credentials */
        $credentials = MultiFactorCredential::query()
            ->whereIn('type', ['webauthn', 'passkey'])
            ->get();

        /** @var null|MultiFactorCredential $storedCredential */
        $storedCredential = $credentials->first(function (MultiFactorCredential $multiFactorCredential, int $key) use ($credentialId): bool {
            /** @var PublicKeyCredentialSource $source */
            $source = WebAuthnSerializer::create()->fromJson(
                $multiFactorCredential->secret,
                PublicKeyCredentialSource::class,
            );

            return mb_convert_encoding($source->publicKeyCredentialId, 'UTF-8') === $credentialId;
        });

        throw_if($storedCredential === null, InvalidWebAuthnAssertionException::class, 'Credential not found.');

        return $storedCredential;
    }

    /**
     * Deserialize PublicKeyCredentialRequestOptions from JSON.
     *
     * @param string $optionsJson JSON string
     *
     * @throws InvalidWebAuthnAssertionException If JSON is invalid
     * @return PublicKeyCredentialRequestOptions Deserialized options
     */
    private function deserializeOptions(string $optionsJson): PublicKeyCredentialRequestOptions
    {
        throw_unless(json_validate($optionsJson), InvalidWebAuthnAssertionException::class, 'Invalid authentication options JSON.');

        /** @var PublicKeyCredentialRequestOptions */
        return WebAuthnSerializer::create()->fromJson(
            $optionsJson,
            PublicKeyCredentialRequestOptions::class,
        );
    }

    /**
     * Update stored credential with new signature counter and usage timestamp.
     *
     * The signature counter prevents cloning attacks by ensuring each
     * authentication increments the counter. We also track when the
     * credential was last used.
     *
     * @param MultiFactorCredential     $credential Credential to update
     * @param PublicKeyCredentialSource $source     Updated source with new counter
     */
    private function updateCredential(
        MultiFactorCredential $credential,
        PublicKeyCredentialSource $source,
    ): void {
        $credential->update([
            'secret' => WebAuthnSerializer::create()->toJson($source),
            'last_used_at' => now(),
        ]);
    }
}
