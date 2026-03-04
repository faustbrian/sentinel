<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\WebAuthn\Support;

use Cline\Sentinel\Contracts\AuthenticatorAssertionValidator;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

/**
 * WebAuthn assertion validator implementation.
 *
 * Wraps the web-auth/webauthn-framework validator to provide
 * cryptographic verification of WebAuthn authentication assertions.
 * @psalm-immutable
 * @author Brian Faust <brian@cline.sh>
 */
final readonly class WebAuthnAssertionValidator implements AuthenticatorAssertionValidator
{
    /**
     * Create a new WebAuthn assertion validator.
     *
     * @param AuthenticatorAssertionResponseValidator $validator WebAuthn library validator
     */
    public function __construct(
        private AuthenticatorAssertionResponseValidator $validator,
    ) {}

    /**
     * Create validator instance with default ceremony configuration.
     */
    public static function createDefault(): self
    {
        $ceremonyFactory = new CeremonyStepManagerFactory();
        $ceremonyStepping = $ceremonyFactory->requestCeremony();
        $validator = AuthenticatorAssertionResponseValidator::create($ceremonyStepping);

        return new self($validator);
    }

    /**
     * {@inheritDoc}
     */
    public function check(
        PublicKeyCredentialSource $publicKeyCredentialSource,
        AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        string $host,
        ?string $userHandle,
    ): PublicKeyCredentialSource {
        return $this->validator->check(
            publicKeyCredentialSource: $publicKeyCredentialSource,
            authenticatorAssertionResponse: $authenticatorAssertionResponse,
            publicKeyCredentialRequestOptions: $publicKeyCredentialRequestOptions,
            host: $host,
            userHandle: $userHandle,
        );
    }
}
