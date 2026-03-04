<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\Contracts;

use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

/**
 * Contract for validating WebAuthn authentication assertions.
 *
 * Defines the interface for verifying cryptographic signatures and
 * validating WebAuthn ceremony requirements during authentication.
 * @author Brian Faust <brian@cline.sh>
 */
interface AuthenticatorAssertionValidator
{
    /**
     * Validate and verify a WebAuthn authentication assertion.
     *
     * @param PublicKeyCredentialSource         $publicKeyCredentialSource         Stored credential with public key
     * @param AuthenticatorAssertionResponse    $authenticatorAssertionResponse    Assertion from browser
     * @param PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions Original challenge options
     * @param string                            $host                              Request hostname
     * @param null|string                       $userHandle                        Optional user handle
     *
     * @return PublicKeyCredentialSource Updated credential source with new counter
     */
    public function check(
        PublicKeyCredentialSource $publicKeyCredentialSource,
        AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        string $host,
        ?string $userHandle,
    ): PublicKeyCredentialSource;
}
