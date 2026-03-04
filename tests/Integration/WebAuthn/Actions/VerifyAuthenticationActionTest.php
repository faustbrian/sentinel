<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Contracts\AuthenticatorAssertionValidator;
use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\Exceptions\InvalidWebAuthnAssertionException;
use Cline\Sentinel\WebAuthn\Actions\VerifyAuthenticationAction;
use Cline\Sentinel\WebAuthn\Support\WebAuthnSerializer;
use Illuminate\Support\Str;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

beforeEach(function (): void {
    $this->user = createUser();
    $this->serializer = WebAuthnSerializer::create();
});

/**
 * Helper to create a test action with mocked validator.
 *
 * For integration tests, we mock only the cryptographic validation
 * but test all other logic including database operations.
 */
function createActionWithMockedValidator(PublicKeyCredentialSource $updatedSource): VerifyAuthenticationAction
{
    $mockValidator = Mockery::mock(AuthenticatorAssertionValidator::class);
    $mockValidator->shouldReceive('check')
        ->andReturn($updatedSource);

    return new VerifyAuthenticationAction($mockValidator);
}

/**
 * Helper to create action for sad path tests.
 *
 * These tests expect exceptions before the validator is called,
 * so we provide a mock that should never be invoked.
 */
function createActionForSadPath(): VerifyAuthenticationAction
{
    $mockValidator = Mockery::mock(AuthenticatorAssertionValidator::class);
    $mockValidator->shouldNotReceive('check');

    return new VerifyAuthenticationAction($mockValidator);
}

/**
 * Helper to create valid WebAuthn assertion JSON for testing.
 * This creates JSON as it would come from a browser, with proper base64url encoding.
 */
function createWebAuthnAssertionJson(string $credentialId): string
{
    $clientDataArray = [
        'type' => 'webauthn.get',
        'challenge' => Base64UrlSafe::encodeUnpadded(random_bytes(32)),
        'origin' => 'https://localhost',
    ];

    // Construct minimal authenticator data (37 bytes minimum)
    // Format: rpIdHash (32) + flags (1) + signCount (4)
    $rpIdHash = hash('sha256', 'localhost', true);
    $flags = chr(0b00000001); // User present
    $signCount = pack('N', 0); // 4 bytes, big-endian
    $authenticatorData = $rpIdHash.$flags.$signCount;

    return json_encode([
        'id' => Base64UrlSafe::encodeUnpadded($credentialId),
        'rawId' => Base64UrlSafe::encodeUnpadded($credentialId),
        'type' => 'public-key',
        'response' => [
            'clientDataJSON' => Base64UrlSafe::encodeUnpadded(json_encode($clientDataArray)),
            'authenticatorData' => Base64UrlSafe::encodeUnpadded($authenticatorData),
            'signature' => Base64UrlSafe::encodeUnpadded(random_bytes(64)),
            'userHandle' => null,
        ],
    ]);
}

describe('Happy Path - Valid Authentication Flow', function (): void {
    test('successfully verifies authentication and updates credential', function (): void {
        // Arrange
        $credentialId = random_bytes(16);
        $initialCounter = 42;

        // Create stored credential source
        $storedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: ['usb'],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::v4(),
            credentialPublicKey: random_bytes(77),
            userHandle: (string) $this->user->id,
            counter: $initialCounter,
        );

        $credential = MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'Security Key',
            'secret' => $this->serializer->toJson($storedSource),
            'created_at' => now(),
            'last_used_at' => null,
        ]);

        // Create updated source with incremented counter
        $updatedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: ['usb'],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: $storedSource->aaguid,
            credentialPublicKey: $storedSource->credentialPublicKey,
            userHandle: (string) $this->user->id,
            counter: $initialCounter + 1,
        );

        // Create valid WebAuthn assertion JSON as it would come from browser
        $credentialJson = createWebAuthnAssertionJson($credentialId);

        // Create valid request options
        $options = PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes(32),
        );
        $optionsJson = $this->serializer->toJson($options);

        // Use action with mocked validator
        $action = createActionWithMockedValidator($updatedSource);

        // Act
        $result = $action->execute(
            credentialJson: $credentialJson,
            optionsJson: $optionsJson,
            hostname: 'localhost',
        );

        // Assert
        expect($result)->toBeInstanceOf(MultiFactorCredential::class)
            ->and($result->id)->toBe($credential->id)
            ->and($result->user_id)->toBe($this->user->id);

        // Verify database was updated
        $credential->refresh();

        $deserializedSource = $this->serializer->fromJson(
            $credential->secret,
            PublicKeyCredentialSource::class,
        );

        expect($deserializedSource->counter)->toBe($initialCounter + 1)
            ->and($credential->last_used_at)->not->toBeNull()
            ->and($credential->last_used_at->timestamp)->toBeGreaterThan(now()->subMinute()->timestamp);
    });

    test('updates last_used_at timestamp on successful authentication', function (): void {
        // Arrange
        $credentialId = random_bytes(16);
        $oldTimestamp = now()->subDay();

        $storedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::v4(),
            credentialPublicKey: random_bytes(77),
            userHandle: (string) $this->user->id,
            counter: 10,
        );

        $credential = MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'Security Key',
            'secret' => $this->serializer->toJson($storedSource),
            'created_at' => now()->subWeek(),
            'last_used_at' => $oldTimestamp,
        ]);

        $updatedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: $storedSource->aaguid,
            credentialPublicKey: $storedSource->credentialPublicKey,
            userHandle: (string) $this->user->id,
            counter: 11,
        );

        $credentialJson = createWebAuthnAssertionJson($credentialId);
        $optionsJson = $this->serializer->toJson(PublicKeyCredentialRequestOptions::create(random_bytes(32)));

        $action = createActionWithMockedValidator($updatedSource);

        // Act
        $action->execute($credentialJson, $optionsJson, 'localhost');

        // Assert
        $credential->refresh();
        expect($credential->last_used_at->isAfter($oldTimestamp))->toBeTrue()
            ->and($credential->last_used_at->isAfter(now()->subMinute()))->toBeTrue();
    });

    test('successfully authenticates with passkey type credential', function (): void {
        // Arrange
        $credentialId = random_bytes(16);

        $storedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: ['internal'],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::v4(),
            credentialPublicKey: random_bytes(77),
            userHandle: (string) $this->user->id,
            counter: 5,
        );

        $credential = MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'passkey',
            'name' => 'Platform Passkey',
            'secret' => $this->serializer->toJson($storedSource),
            'created_at' => now(),
        ]);

        $updatedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: ['internal'],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: $storedSource->aaguid,
            credentialPublicKey: $storedSource->credentialPublicKey,
            userHandle: (string) $this->user->id,
            counter: 6,
        );

        $credentialJson = createWebAuthnAssertionJson($credentialId);
        $optionsJson = $this->serializer->toJson(PublicKeyCredentialRequestOptions::create(random_bytes(32)));

        $action = createActionWithMockedValidator($updatedSource);

        // Act
        $result = $action->execute($credentialJson, $optionsJson, 'localhost');

        // Assert
        expect($result->id)->toBe($credential->id)
            ->and($result->type)->toBe('passkey');
    });
});

describe('Sad Path - Credential Not Found', function (): void {
    test('throws exception when credential ID does not match any stored credentials', function (): void {
        // Arrange - Create a credential with ID that won't match
        $storedCredentialId = random_bytes(16);
        $storedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $storedCredentialId,
            type: 'public-key',
            transports: [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::v4(),
            credentialPublicKey: random_bytes(77),
            userHandle: (string) $this->user->id,
            counter: 0,
        );

        MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'Security Key',
            'secret' => $this->serializer->toJson($storedSource),
            'created_at' => now(),
        ]);

        // Create credential with different ID
        $differentCredentialId = random_bytes(16);

        $credentialJson = createWebAuthnAssertionJson($differentCredentialId);
        $optionsJson = $this->serializer->toJson(PublicKeyCredentialRequestOptions::create(random_bytes(32)));

        $action = createActionForSadPath();

        // Act & Assert
        expect(fn (): MultiFactorCredential => $action->execute($credentialJson, $optionsJson, 'localhost'))
            ->toThrow(InvalidWebAuthnAssertionException::class, 'Credential not found.');
    });

    test('ignores totp credentials when searching for webauthn credentials', function (): void {
        // Arrange - Only create TOTP credential
        createTotpCredential($this->user);

        $credentialId = random_bytes(16);

        $credentialJson = createWebAuthnAssertionJson($credentialId);
        $optionsJson = $this->serializer->toJson(PublicKeyCredentialRequestOptions::create(random_bytes(32)));

        $action = createActionForSadPath();

        // Act & Assert
        expect(fn (): MultiFactorCredential => $action->execute($credentialJson, $optionsJson, 'localhost'))
            ->toThrow(InvalidWebAuthnAssertionException::class, 'Credential not found.');
    });
});

describe('Sad Path - Invalid JSON', function (): void {
    test('throws exception for invalid credential JSON', function (): void {
        // Arrange
        $invalidJson = 'not valid json';
        $action = createActionForSadPath();

        // Act & Assert
        expect(fn (): MultiFactorCredential => $action->execute($invalidJson, '{}', 'localhost'))
            ->toThrow(InvalidWebAuthnAssertionException::class, 'Invalid credential JSON.');
    });

    test('throws exception for malformed credential JSON', function (): void {
        // Arrange
        $malformedJson = '{invalid: json}';
        $action = createActionForSadPath();

        // Act & Assert
        expect(fn (): MultiFactorCredential => $action->execute($malformedJson, '{}', 'localhost'))
            ->toThrow(InvalidWebAuthnAssertionException::class, 'Invalid credential JSON.');
    });

    test('throws exception for empty credential JSON', function (): void {
        // Arrange
        $emptyJson = '';
        $action = createActionForSadPath();

        // Act & Assert
        expect(fn (): MultiFactorCredential => $action->execute($emptyJson, '{}', 'localhost'))
            ->toThrow(InvalidWebAuthnAssertionException::class, 'Invalid credential JSON.');
    });

    test('throws exception for invalid options JSON', function (): void {
        // Arrange
        $credentialId = random_bytes(16);
        $storedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::v4(),
            credentialPublicKey: random_bytes(77),
            userHandle: (string) $this->user->id,
            counter: 0,
        );

        MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'Security Key',
            'secret' => $this->serializer->toJson($storedSource),
            'created_at' => now(),
        ]);

        $credentialJson = createWebAuthnAssertionJson($credentialId);
        $invalidOptionsJson = 'invalid json';

        $action = createActionForSadPath();

        // Act & Assert
        expect(fn (): MultiFactorCredential => $action->execute($credentialJson, $invalidOptionsJson, 'localhost'))
            ->toThrow(InvalidWebAuthnAssertionException::class, 'Invalid authentication options JSON.');
    });

    test('throws exception for malformed options JSON', function (): void {
        // Arrange
        $credentialId = random_bytes(16);
        $storedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::v4(),
            credentialPublicKey: random_bytes(77),
            userHandle: (string) $this->user->id,
            counter: 0,
        );

        MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'Security Key',
            'secret' => $this->serializer->toJson($storedSource),
            'created_at' => now(),
        ]);

        $credentialJson = createWebAuthnAssertionJson($credentialId);
        $malformedOptionsJson = '{malformed}';

        $action = createActionForSadPath();

        // Act & Assert
        expect(fn (): MultiFactorCredential => $action->execute($credentialJson, $malformedOptionsJson, 'localhost'))
            ->toThrow(InvalidWebAuthnAssertionException::class, 'Invalid authentication options JSON.');
    });
});

describe('Sad Path - Invalid Response Type', function (): void {
    test('throws exception when credential response is not AuthenticatorAssertionResponse', function (): void {
        // This test is hard to achieve with real objects since PublicKeyCredential
        // requires AuthenticatorResponse in constructor.  We can test via JSON deserialization
        $credentialId = random_bytes(16);

        // Create JSON that will deserialize but has wrong response type
        $invalidJson = json_encode([
            'id' => base64_encode($credentialId),
            'rawId' => base64_encode($credentialId),
            'type' => 'public-key',
            'response' => [
                // This will deserialize to wrong type
                'clientDataJSON' => base64_encode('{}'),
                'attestationObject' => base64_encode('invalid'),
            ],
        ]);

        $action = createActionForSadPath();

        // Act & Assert - Will throw during deserialization or validation
        expect(fn (): MultiFactorCredential => $action->execute($invalidJson, '{}', 'localhost'))
            ->toThrow(Exception::class);
    });
});

describe('Edge Cases - Credential Lookup with Encoding', function (): void {
    test('correctly finds credential using mb_convert_encoding', function (): void {
        // Arrange - Create multiple credentials
        $targetCredentialId = random_bytes(32);
        $otherCredentialId1 = random_bytes(32);
        $otherCredentialId2 = random_bytes(32);

        foreach ([$otherCredentialId1, $targetCredentialId, $otherCredentialId2] as $index => $credId) {
            $source = PublicKeyCredentialSource::create(
                publicKeyCredentialId: $credId,
                type: 'public-key',
                transports: [],
                attestationType: 'none',
                trustPath: new EmptyTrustPath(),
                aaguid: Uuid::v4(),
                credentialPublicKey: random_bytes(77),
                userHandle: (string) $this->user->id,
                counter: $index,
            );

            MultiFactorCredential::query()->create([
                'id' => Str::uuid()->toString(),
                'user_id' => $this->user->id,
                'type' => $index === 1 ? 'webauthn' : 'passkey',
                'name' => 'Key '.$index,
                'secret' => $this->serializer->toJson($source),
                'created_at' => now(),
            ]);
        }

        $updatedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $targetCredentialId,
            type: 'public-key',
            transports: [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::v4(),
            credentialPublicKey: random_bytes(77),
            userHandle: (string) $this->user->id,
            counter: 2,
        );

        $credentialJson = createWebAuthnAssertionJson($targetCredentialId);
        $optionsJson = $this->serializer->toJson(PublicKeyCredentialRequestOptions::create(random_bytes(32)));

        $action = createActionWithMockedValidator($updatedSource);

        // Act
        $result = $action->execute($credentialJson, $optionsJson, 'localhost');

        // Assert
        expect($result->name)->toBe('Key 1');
    });
});

describe('Edge Cases - Signature Counter Updates', function (): void {
    test('updates credential with new counter value from validator', function (): void {
        // Arrange
        $credentialId = random_bytes(16);
        $initialCounter = 100;
        $newCounter = 150;

        $storedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::v4(),
            credentialPublicKey: random_bytes(77),
            userHandle: (string) $this->user->id,
            counter: $initialCounter,
        );

        $credential = MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'Security Key',
            'secret' => $this->serializer->toJson($storedSource),
            'created_at' => now(),
        ]);

        $updatedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: $storedSource->aaguid,
            credentialPublicKey: $storedSource->credentialPublicKey,
            userHandle: (string) $this->user->id,
            counter: $newCounter,
        );

        $credentialJson = createWebAuthnAssertionJson($credentialId);
        $optionsJson = $this->serializer->toJson(PublicKeyCredentialRequestOptions::create(random_bytes(32)));

        $action = createActionWithMockedValidator($updatedSource);

        // Act
        $action->execute($credentialJson, $optionsJson, 'localhost');

        // Assert
        $credential->refresh();
        $deserializedSource = $this->serializer->fromJson(
            $credential->secret,
            PublicKeyCredentialSource::class,
        );

        expect($deserializedSource->counter)->toBe($newCounter)
            ->and($deserializedSource->counter)->not->toBe($initialCounter);
    });

    test('persists all credential source properties after update', function (): void {
        // Arrange
        $credentialId = random_bytes(16);
        $aaguid = Uuid::v4();
        $publicKey = random_bytes(77);
        $transports = ['usb', 'nfc'];

        $storedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: $transports,
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: $aaguid,
            credentialPublicKey: $publicKey,
            userHandle: (string) $this->user->id,
            counter: 10,
        );

        $credential = MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'Security Key',
            'secret' => $this->serializer->toJson($storedSource),
            'created_at' => now(),
        ]);

        $updatedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: $transports,
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: $aaguid,
            credentialPublicKey: $publicKey,
            userHandle: (string) $this->user->id,
            counter: 11,
        );

        $credentialJson = createWebAuthnAssertionJson($credentialId);
        $optionsJson = $this->serializer->toJson(PublicKeyCredentialRequestOptions::create(random_bytes(32)));

        $action = createActionWithMockedValidator($updatedSource);

        // Act
        $action->execute($credentialJson, $optionsJson, 'localhost');

        // Assert - Verify all properties are preserved
        $credential->refresh();
        $deserializedSource = $this->serializer->fromJson(
            $credential->secret,
            PublicKeyCredentialSource::class,
        );

        expect($deserializedSource->publicKeyCredentialId)->toBe($credentialId)
            ->and($deserializedSource->type)->toBe('public-key')
            ->and($deserializedSource->transports)->toBe($transports)
            ->and($deserializedSource->aaguid->toRfc4122())->toBe($aaguid->toRfc4122())
            ->and($deserializedSource->credentialPublicKey)->toBe($publicKey)
            ->and($deserializedSource->counter)->toBe(11);
    });
});

describe('Integration - User Relationship', function (): void {
    test('returned credential maintains user relationship', function (): void {
        // Arrange
        $credentialId = random_bytes(16);

        $storedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::v4(),
            credentialPublicKey: random_bytes(77),
            userHandle: (string) $this->user->id,
            counter: 0,
        );

        MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'Security Key',
            'secret' => $this->serializer->toJson($storedSource),
            'created_at' => now(),
        ]);

        $updatedSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: $storedSource->aaguid,
            credentialPublicKey: $storedSource->credentialPublicKey,
            userHandle: (string) $this->user->id,
            counter: 1,
        );

        $credentialJson = createWebAuthnAssertionJson($credentialId);
        $optionsJson = $this->serializer->toJson(PublicKeyCredentialRequestOptions::create(random_bytes(32)));

        $action = createActionWithMockedValidator($updatedSource);

        // Act
        $result = $action->execute($credentialJson, $optionsJson, 'localhost');

        // Assert
        expect($result->user)->not->toBeNull()
            ->and($result->user->id)->toBe($this->user->id)
            ->and($result->user->email)->toBe($this->user->email);
    });
});
