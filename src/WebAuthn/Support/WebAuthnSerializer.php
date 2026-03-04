<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\WebAuthn\Support;

use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Exception\ExceptionInterface;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\Serializer as SymfonySerializer;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

use const JSON_THROW_ON_ERROR;

/**
 * Serializer for WebAuthn protocol objects.
 *
 * Handles serialization and deserialization of WebAuthn objects to/from JSON
 * using the official web-auth/webauthn-lib serialization factory. This ensures
 * proper handling of binary data, cryptographic objects, and protocol-specific
 * structures required by the WebAuthn specification.
 *
 * Common use cases:
 * - Converting PublicKeyCredentialCreationOptions to JSON for browser
 * - Deserializing PublicKeyCredential responses from browser
 * - Storing/retrieving credential sources in database
 * - Marshaling challenge options to/from session storage
 *
 * ```php
 * $serializer = WebAuthnSerializer::create();
 *
 * // Serialize options for JavaScript
 * $json = $serializer->toJson($creationOptions);
 *
 * // Deserialize browser response
 * $credential = $serializer->fromJson($json, PublicKeyCredential::class);
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class WebAuthnSerializer
{
    /**
     * Create a new WebAuthn serializer instance.
     *
     * @param SymfonySerializer $serializer Configured Symfony serializer with WebAuthn support.
     *                                      Use create() factory method for automatic configuration.
     */
    public function __construct(
        private SymfonySerializer $serializer,
    ) {}

    /**
     * Create a new serializer instance with WebAuthn support.
     *
     * Initializes the Symfony serializer with WebAuthn-specific normalizers
     * and attestation statement support. The factory handles all WebAuthn
     * denormalizers automatically.
     *
     * @return self Configured serializer ready for WebAuthn operations
     */
    public static function create(): self
    {
        $attestationStatementSupportManager = AttestationStatementSupportManager::create();

        /** @var SymfonySerializer $serializer */
        $serializer = new WebauthnSerializerFactory($attestationStatementSupportManager)->create();

        return new self($serializer);
    }

    /**
     * Serialize a WebAuthn object to JSON.
     *
     * Converts WebAuthn protocol objects (PublicKeyCredentialCreationOptions,
     * PublicKeyCredentialRequestOptions, etc.) to JSON format suitable for
     * transmission to browser or storage. Automatically handles binary data
     * encoding, null value skipping, and proper JSON formatting.
     *
     * @param mixed $value WebAuthn object to serialize (e.g., PublicKeyCredentialCreationOptions)
     *
     * @throws ExceptionInterface If serialization fails
     * @return string             JSON representation of the object
     */
    public function toJson(mixed $value): string
    {
        return $this->serializer->serialize(
            $value,
            'json',
            [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
            ],
        );
    }

    /**
     * Deserialize JSON to a WebAuthn object.
     *
     * Converts JSON string back to WebAuthn protocol objects. Commonly used
     * to deserialize browser responses (PublicKeyCredential) or retrieve
     * stored credential sources from database.
     *
     * @param string       $value        JSON string to deserialize
     * @param class-string $desiredClass Target class to deserialize into
     *                                   (e.g., PublicKeyCredential::class,
     *                                   PublicKeyCredentialSource::class)
     *
     * @throws ExceptionInterface If deserialization fails
     * @return mixed              Deserialized WebAuthn object of the specified class
     */
    public function fromJson(string $value, string $desiredClass): mixed
    {
        return $this->serializer->deserialize($value, $desiredClass, 'json');
    }
}
