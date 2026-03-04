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
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

beforeEach(function (): void {
    $this->user = createUser();

    // Mock validator for unit testing - shouldn't be called in these sad path tests
    $mockValidator = Mockery::mock(AuthenticatorAssertionValidator::class);
    $mockValidator->shouldNotReceive('check');

    $this->action = new VerifyAuthenticationAction($mockValidator);
    $this->serializer = WebAuthnSerializer::create();
});

describe('Sad Path - Invalid Credential JSON', function (): void {
    test('throws exception for invalid credential JSON', function (): void {
        $this->action->execute(
            credentialJson: 'invalid json',
            optionsJson: '{}',
            hostname: 'localhost',
        );
    })->throws(InvalidWebAuthnAssertionException::class, 'Invalid credential JSON.');

    test('throws exception for malformed credential JSON with syntax error', function (): void {
        $this->action->execute(
            credentialJson: '{invalid}',
            optionsJson: '{}',
            hostname: 'localhost',
        );
    })->throws(InvalidWebAuthnAssertionException::class, 'Invalid credential JSON.');

    test('throws exception for empty credential JSON string', function (): void {
        $this->action->execute(
            credentialJson: '',
            optionsJson: '{}',
            hostname: 'localhost',
        );
    })->throws(InvalidWebAuthnAssertionException::class, 'Invalid credential JSON.');

    test('throws exception for JSON that passes json_validate but not WebAuthn deserialization', function (): void {
        // Valid JSON structure but won't deserialize to PublicKeyCredential
        $validJsonInvalidWebAuthn = json_encode(['foo' => 'bar']);

        expect(json_validate($validJsonInvalidWebAuthn))->toBeTrue();

        $this->action->execute(
            credentialJson: $validJsonInvalidWebAuthn,
            optionsJson: '{}',
            hostname: 'localhost',
        );
    })->throws(Exception::class); // Will throw some deserialization exception
});

describe('Edge Cases - Credential Lookup and Encoding', function (): void {
    test('finds correct credential when multiple webauthn credentials exist', function (): void {
        // Create multiple credentials with different IDs
        $credentialId1 = random_bytes(16);
        $credentialId2 = random_bytes(16);
        $credentialId3 = random_bytes(16);

        foreach ([$credentialId1, $credentialId2, $credentialId3] as $index => $credId) {
            $source = PublicKeyCredentialSource::create(
                publicKeyCredentialId: $credId,
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
                'name' => 'Key '.($index + 1),
                'secret' => $this->serializer->toJson($source),
                'created_at' => now(),
            ]);
        }

        // Verify all three credentials are searchable
        $credentials = MultiFactorCredential::query()
            ->whereIn('type', ['webauthn', 'passkey'])
            ->get();

        expect($credentials)->toHaveCount(3);

        // Test that we can find each specific credential by ID
        foreach ([$credentialId1, $credentialId2, $credentialId3] as $credId) {
            $searchId = mb_convert_encoding($credId, 'UTF-8');
            $found = $credentials->first(function (MultiFactorCredential $multiFactorCredential) use ($searchId): bool {
                $source = $this->serializer->fromJson(
                    $multiFactorCredential->secret,
                    PublicKeyCredentialSource::class,
                );

                return mb_convert_encoding($source->publicKeyCredentialId, 'UTF-8') === $searchId;
            });

            expect($found)->not->toBeNull();
        }
    });

    test('handles both webauthn and passkey credential types', function (): void {
        // Create one of each type
        $webauthnCredId = random_bytes(16);
        $passkeyCredId = random_bytes(16);

        $webauthnSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $webauthnCredId,
            type: 'public-key',
            transports: [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::v4(),
            credentialPublicKey: random_bytes(77),
            userHandle: (string) $this->user->id,
            counter: 0,
        );

        $passkeySource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $passkeyCredId,
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
            'secret' => $this->serializer->toJson($webauthnSource),
            'created_at' => now(),
        ]);

        MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'passkey',
            'name' => 'Platform Passkey',
            'secret' => $this->serializer->toJson($passkeySource),
            'created_at' => now(),
        ]);

        // Verify both types are retrieved by whereIn query
        $credentials = MultiFactorCredential::query()
            ->whereIn('type', ['webauthn', 'passkey'])
            ->get();

        expect($credentials)->toHaveCount(2);

        // Verify we can find both by their IDs
        $webauthnFound = $credentials->first(fn (MultiFactorCredential $cred): bool => $cred->type === 'webauthn');

        $passkeyFound = $credentials->first(fn (MultiFactorCredential $cred): bool => $cred->type === 'passkey');

        expect($webauthnFound)->not->toBeNull()
            ->and($passkeyFound)->not->toBeNull()
            ->and($webauthnFound->name)->toBe('Security Key')
            ->and($passkeyFound->name)->toBe('Platform Passkey');
    });

    test('handles UTF-8 encoding correctly with mb_convert_encoding', function (): void {
        // Create credential with larger binary ID that tests encoding edge cases
        $credentialId = random_bytes(32);

        $source = PublicKeyCredentialSource::create(
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
            'secret' => $this->serializer->toJson($source),
            'created_at' => now(),
        ]);

        // Verify encoding works correctly
        $searchId = mb_convert_encoding($credentialId, 'UTF-8');
        $credentials = MultiFactorCredential::query()
            ->whereIn('type', ['webauthn', 'passkey'])
            ->get();

        $found = $credentials->first(function (MultiFactorCredential $multiFactorCredential) use ($searchId): bool {
            $source = $this->serializer->fromJson(
                $multiFactorCredential->secret,
                PublicKeyCredentialSource::class,
            );

            return mb_convert_encoding($source->publicKeyCredentialId, 'UTF-8') === $searchId;
        });

        expect($found)->not->toBeNull();
    });

    test('collection first returns null when no credentials match', function (): void {
        // Create credential with specific ID
        $storedCredentialId = random_bytes(16);

        $source = PublicKeyCredentialSource::create(
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
            'name' => 'Key 1',
            'secret' => $this->serializer->toJson($source),
            'created_at' => now(),
        ]);

        // Search for completely different credential ID
        $differentCredentialId = random_bytes(16);
        $searchId = mb_convert_encoding($differentCredentialId, 'UTF-8');

        $credentials = MultiFactorCredential::query()
            ->whereIn('type', ['webauthn', 'passkey'])
            ->get();

        $found = $credentials->first(function (MultiFactorCredential $multiFactorCredential) use ($searchId): bool {
            $source = $this->serializer->fromJson(
                $multiFactorCredential->secret,
                PublicKeyCredentialSource::class,
            );

            return mb_convert_encoding($source->publicKeyCredentialId, 'UTF-8') === $searchId;
        });

        expect($found)->toBeNull();
    });

    test('credential source serialization and deserialization preserves all properties', function (): void {
        $credentialId = random_bytes(16);
        $aaguid = Uuid::v4();
        $publicKey = random_bytes(77);
        $userHandle = (string) $this->user->id;

        $originalSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: ['usb', 'nfc'],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: $aaguid,
            credentialPublicKey: $publicKey,
            userHandle: $userHandle,
            counter: 42,
        );

        $serialized = $this->serializer->toJson($originalSource);

        MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'Security Key',
            'secret' => $serialized,
            'created_at' => now(),
        ]);

        // Retrieve and deserialize
        $credential = MultiFactorCredential::query()->first();
        $deserializedSource = $this->serializer->fromJson(
            $credential->secret,
            PublicKeyCredentialSource::class,
        );

        expect($deserializedSource->publicKeyCredentialId)->toBe($credentialId)
            ->and($deserializedSource->type)->toBe('public-key')
            ->and($deserializedSource->transports)->toBe(['usb', 'nfc'])
            ->and($deserializedSource->counter)->toBe(42)
            ->and($deserializedSource->userHandle)->toBe($userHandle)
            ->and($deserializedSource->aaguid->toRfc4122())->toBe($aaguid->toRfc4122());
    });
});
