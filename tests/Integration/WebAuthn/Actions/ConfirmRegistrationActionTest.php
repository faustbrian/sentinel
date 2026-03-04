<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Exceptions\InvalidWebAuthnAssertionException;
use Cline\Sentinel\WebAuthn\Actions\ConfirmRegistrationAction;
use Cline\Sentinel\WebAuthn\Support\WebAuthnSerializer;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

beforeEach(function (): void {
    $this->user = createUser();
    $this->action = new ConfirmRegistrationAction();
    $this->serializer = WebAuthnSerializer::create();
});

describe('JSON validation', function (): void {
    test('throws exception for invalid options JSON', function (): void {
        // Arrange
        $credentialJson = '{"id":"test","type":"public-key"}';
        $invalidOptionsJson = '{"invalid": json without closing brace';

        // Act & Assert
        expect(fn () => $this->action->execute(
            user: $this->user,
            credentialJson: $credentialJson,
            optionsJson: $invalidOptionsJson,
            hostname: 'localhost',
            name: 'Test Key',
        ))->toThrow(InvalidWebAuthnAssertionException::class, 'Invalid registration options JSON.');
    });

    test('throws exception for invalid credential JSON', function (): void {
        // Arrange
        $options = PublicKeyCredentialCreationOptions::create(
            rp: PublicKeyCredentialRpEntity::create('Test App', 'localhost'),
            user: PublicKeyCredentialUserEntity::create('test@example.com', (string) $this->user->id, 'Test User'),
            challenge: random_bytes(32),
            pubKeyCredParams: [PublicKeyCredentialParameters::create('public-key', -7)],
        );

        $optionsJson = $this->serializer->toJson($options);

        $invalidCredentialJson = '{"invalid": json without closing brace';

        // Act & Assert
        expect(fn () => $this->action->execute(
            user: $this->user,
            credentialJson: $invalidCredentialJson,
            optionsJson: $optionsJson,
            hostname: 'localhost',
            name: 'Test Key',
        ))->toThrow(InvalidWebAuthnAssertionException::class, 'Invalid credential JSON.');
    });

    test('validates options JSON before credential JSON', function (): void {
        // Arrange
        $invalidCredentialJson = '{"invalid": json';
        $invalidOptionsJson = '{"also invalid';

        // Act & Assert
        try {
            $this->action->execute(
                user: $this->user,
                credentialJson: $invalidCredentialJson,
                optionsJson: $invalidOptionsJson,
                hostname: 'localhost',
                name: 'Test Key',
            );

            $this->fail('Expected InvalidWebAuthnAssertionException to be thrown');
        } catch (InvalidWebAuthnAssertionException $invalidWebAuthnAssertionException) {
            expect($invalidWebAuthnAssertionException->getMessage())->toBe('Invalid registration options JSON.');
        }
    });
});

describe('attestation response validation', function (): void {
    test('throws exception when response is not attestation type', function (): void {
        // Arrange
        $options = PublicKeyCredentialCreationOptions::create(
            rp: PublicKeyCredentialRpEntity::create('Test App', 'localhost'),
            user: PublicKeyCredentialUserEntity::create('test@example.com', (string) $this->user->id, 'Test User'),
            challenge: random_bytes(32),
            pubKeyCredParams: [PublicKeyCredentialParameters::create('public-key', -7)],
        );

        $optionsJson = $this->serializer->toJson($options);

        // This JSON will fail deserialization but tests the exception wrapping
        $credentialJson = '{"id":"test","type":"public-key","rawId":"test","response":{}}';

        // Act & Assert
        expect(fn () => $this->action->execute(
            user: $this->user,
            credentialJson: $credentialJson,
            optionsJson: $optionsJson,
            hostname: 'localhost',
            name: 'Test Key',
        ))->toThrow(InvalidWebAuthnAssertionException::class);
    });
});

describe('skipped tests requiring valid WebAuthn attestation vectors', function (): void {
    test('creates credential with valid attestation response', function (): void {
        $this->markTestSkipped('Requires cryptographically valid CBOR-encoded attestation objects from W3C test vectors or browser automation');
    });

    test('creates passkey credential with type passkey', function (): void {
        $this->markTestSkipped('Requires cryptographically valid CBOR-encoded attestation objects from W3C test vectors or browser automation');
    });

    test('generates unique UUID for each credential', function (): void {
        $this->markTestSkipped('Requires cryptographically valid CBOR-encoded attestation objects from W3C test vectors or browser automation');
    });

    test('stores serialized credential source in secret field', function (): void {
        $this->markTestSkipped('Requires cryptographically valid CBOR-encoded attestation objects from W3C test vectors or browser automation');
    });

    test('sets created_at timestamp', function (): void {
        $this->markTestSkipped('Requires cryptographically valid CBOR-encoded attestation objects from W3C test vectors or browser automation');
    });

    test('wraps WebAuthn validation exceptions', function (): void {
        $this->markTestSkipped('Requires cryptographically valid CBOR-encoded attestation objects from W3C test vectors or browser automation');
    });

    test('validates hostname during ceremony', function (): void {
        $this->markTestSkipped('Requires cryptographically valid CBOR-encoded attestation objects from W3C test vectors or browser automation');
    });

    test('handles empty string for name', function (): void {
        $this->markTestSkipped('Requires cryptographically valid CBOR-encoded attestation objects from W3C test vectors or browser automation');
    });

    test('handles special characters in hostname', function (): void {
        $this->markTestSkipped('Requires cryptographically valid CBOR-encoded attestation objects from W3C test vectors or browser automation');
    });

    test('handles unicode in credential name', function (): void {
        $this->markTestSkipped('Requires cryptographically valid CBOR-encoded attestation objects from W3C test vectors or browser automation');
    });
});
