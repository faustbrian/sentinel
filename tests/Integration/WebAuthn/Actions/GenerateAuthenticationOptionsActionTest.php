<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\WebAuthn\Actions\GenerateAuthenticationOptionsAction;
use Cline\Sentinel\WebAuthn\Support\WebAuthnSerializer;
use Illuminate\Support\Str;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

beforeEach(function (): void {
    $this->user = createUser();
    $this->action = new GenerateAuthenticationOptionsAction();
    $this->serializer = WebAuthnSerializer::create();

    // Set WebAuthn config for testing
    config([
        'sentinel.webauthn.relying_party.id' => 'example.com',
        'sentinel.webauthn.relying_party.name' => 'Test App',
    ]);
});

describe('Happy Path - Generate Options with JSON Response', function (): void {
    test('generates authentication options as JSON for user with webauthn credentials', function (): void {
        // Arrange
        $credentialId = random_bytes(16);
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

        // Verify credential was stored in database
        $this->assertDatabaseHas('multi_factor_credentials', [
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'Security Key',
        ]);

        // Act
        $result = $this->action->execute($this->user, asJson: true);

        // Assert
        expect($result)->toBeString()
            ->and(json_validate($result))->toBeTrue();

        $decoded = json_decode($result, true);
        expect($decoded)->toHaveKey('challenge')
            ->and($decoded)->toHaveKey('rpId')
            ->and($decoded)->toHaveKey('allowCredentials')
            ->and($decoded)->toHaveKey('userVerification')
            ->and($decoded['rpId'])->toBe('example.com')
            ->and($decoded['userVerification'])->toBe('preferred')
            ->and($decoded['allowCredentials'])->toHaveCount(1)
            ->and($decoded['allowCredentials'][0]['type'])->toBe('public-key');
    });

    test('generates authentication options as JSON for user with passkey credentials', function (): void {
        // Arrange
        $credentialId = random_bytes(16);
        $source = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: ['internal'],
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
            'type' => 'passkey',
            'name' => 'Platform Passkey',
            'secret' => $this->serializer->toJson($source),
            'created_at' => now(),
        ]);

        // Act
        $result = $this->action->execute($this->user, asJson: true);

        // Assert
        expect($result)->toBeString()
            ->and(json_validate($result))->toBeTrue();

        $decoded = json_decode($result, true);
        expect($decoded['allowCredentials'])->toHaveCount(1)
            ->and($decoded['allowCredentials'][0]['type'])->toBe('public-key');
    });

    test('generates authentication options as JSON for user with multiple credentials', function (): void {
        // Arrange
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

            $type = $index === 0 ? 'webauthn' : 'passkey';
            MultiFactorCredential::query()->create([
                'id' => Str::uuid()->toString(),
                'user_id' => $this->user->id,
                'type' => $type,
                'name' => 'Key '.($index + 1),
                'secret' => $this->serializer->toJson($source),
                'created_at' => now(),
            ]);
        }

        // Act
        $result = $this->action->execute($this->user, asJson: true);

        // Assert
        expect($result)->toBeString()
            ->and(json_validate($result))->toBeTrue();

        $decoded = json_decode($result, true);
        expect($decoded['allowCredentials'])->toHaveCount(3);

        // Verify all credentials are included
        foreach ($decoded['allowCredentials'] as $credential) {
            expect($credential['type'])->toBe('public-key')
                ->and($credential)->toHaveKey('id');
        }
    });

    test('generates authentication options as JSON for discoverable credentials without user', function (): void {
        // Act
        $result = $this->action->execute(user: null, asJson: true);

        // Assert
        expect($result)->toBeString()
            ->and(json_validate($result))->toBeTrue();

        $decoded = json_decode($result, true);
        expect($decoded)->toHaveKey('challenge')
            ->and($decoded)->toHaveKey('rpId')
            ->and($decoded)->toHaveKey('allowCredentials')
            ->and($decoded)->toHaveKey('userVerification')
            ->and($decoded['rpId'])->toBe('example.com')
            ->and($decoded['userVerification'])->toBe('preferred')
            ->and($decoded['allowCredentials'])->toBeArray()
            ->and($decoded['allowCredentials'])->toBeEmpty(); // No user means empty credentials
    });
});

describe('Happy Path - Generate Options with Object Response', function (): void {
    test('generates authentication options as object for user with credentials', function (): void {
        // Arrange
        $credentialId = random_bytes(16);
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

        // Act
        $result = $this->action->execute($this->user, asJson: false);

        // Assert
        expect($result)->toBeInstanceOf(PublicKeyCredentialRequestOptions::class)
            ->and($result->challenge)->toBeString()
            ->and($result->challenge)->toHaveLength(32)
            ->and($result->rpId)->toBe('example.com')
            ->and($result->userVerification)->toBe(PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED)
            ->and($result->allowCredentials)->toHaveCount(1)
            ->and($result->allowCredentials[0])->toBeInstanceOf(PublicKeyCredentialDescriptor::class)
            ->and($result->allowCredentials[0]->type)->toBe(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY)
            ->and($result->allowCredentials[0]->id)->toBe($credentialId);
    });

    test('generates authentication options as object for user with multiple mixed credentials', function (): void {
        // Arrange
        $webauthnCredId = random_bytes(16);
        $passkeyCredId = random_bytes(16);

        $webauthnSource = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $webauthnCredId,
            type: 'public-key',
            transports: ['usb'],
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
            transports: ['internal'],
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

        // Act
        $result = $this->action->execute($this->user, asJson: false);

        // Assert
        expect($result)->toBeInstanceOf(PublicKeyCredentialRequestOptions::class)
            ->and($result->allowCredentials)->toHaveCount(2);

        // Verify both credential IDs are present
        $credentialIds = array_map(fn ($cred) => $cred->id, $result->allowCredentials);
        expect($credentialIds)->toContain($webauthnCredId)
            ->and($credentialIds)->toContain($passkeyCredId);

        // Verify all are PublicKeyCredentialDescriptor instances
        foreach ($result->allowCredentials as $credential) {
            expect($credential)->toBeInstanceOf(PublicKeyCredentialDescriptor::class)
                ->and($credential->type)->toBe(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY);
        }
    });

    test('generates authentication options as object for discoverable credentials without user', function (): void {
        // Act
        $result = $this->action->execute(user: null, asJson: false);

        // Assert
        expect($result)->toBeInstanceOf(PublicKeyCredentialRequestOptions::class)
            ->and($result->challenge)->toBeString()
            ->and($result->challenge)->toHaveLength(32)
            ->and($result->rpId)->toBe('example.com')
            ->and($result->userVerification)->toBe(PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED)
            ->and($result->allowCredentials)->toBeArray()
            ->and($result->allowCredentials)->toBeEmpty();
    });
});

describe('Edge Cases - Credential Filtering and Mapping', function (): void {
    test('filters out non-webauthn and non-passkey credentials', function (): void {
        // Arrange
        $webauthnCredId = random_bytes(16);
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

        MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'Security Key',
            'secret' => $this->serializer->toJson($webauthnSource),
            'created_at' => now(),
        ]);

        // Create TOTP credential (should be filtered out)
        MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => 'Authenticator App',
            'secret' => 'JBSWY3DPEHPK3PXP',
            'created_at' => now(),
        ]);

        // Act
        $result = $this->action->execute($this->user, asJson: false);

        // Assert
        expect($result->allowCredentials)->toHaveCount(1)
            ->and($result->allowCredentials[0]->id)->toBe($webauthnCredId);
    });

    test('handles user with no webauthn or passkey credentials', function (): void {
        // Arrange - Create only TOTP credential
        MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => 'Authenticator App',
            'secret' => 'JBSWY3DPEHPK3PXP',
            'created_at' => now(),
        ]);

        // Act
        $result = $this->action->execute($this->user, asJson: false);

        // Assert
        expect($result->allowCredentials)->toBeArray()
            ->and($result->allowCredentials)->toBeEmpty();
    });

    test('correctly deserializes and maps credential source to descriptor', function (): void {
        // Arrange
        $credentialId = random_bytes(32);
        $aaguid = Uuid::v4();
        $publicKey = random_bytes(77);

        $source = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: ['usb', 'nfc', 'ble'],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: $aaguid,
            credentialPublicKey: $publicKey,
            userHandle: (string) $this->user->id,
            counter: 42,
        );

        MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'Security Key',
            'secret' => $this->serializer->toJson($source),
            'created_at' => now(),
        ]);

        // Act
        $result = $this->action->execute($this->user, asJson: false);

        // Assert
        expect($result->allowCredentials)->toHaveCount(1);

        $descriptor = $result->allowCredentials[0];
        expect($descriptor)->toBeInstanceOf(PublicKeyCredentialDescriptor::class)
            ->and($descriptor->type)->toBe(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY)
            ->and($descriptor->id)->toBe($credentialId)
            ->and(mb_strlen((string) $descriptor->id))->toBeGreaterThan(0);
    });

    test('challenge is unique for each request', function (): void {
        // Act
        $result1 = $this->action->execute($this->user, asJson: false);
        $result2 = $this->action->execute($this->user, asJson: false);

        // Assert
        expect($result1->challenge)->toBeString()
            ->and($result1->challenge)->toHaveLength(32)
            ->and($result2->challenge)->toBeString()
            ->and($result2->challenge)->toHaveLength(32)
            ->and($result1->challenge)->not->toBe($result2->challenge);
    });
});

describe('Edge Cases - Different User Scenarios', function (): void {
    test('only includes credentials for specified user, not other users', function (): void {
        // Arrange - Create credentials for two different users
        $user1 = $this->user;
        $user2 = createUser('other@example.com');

        $cred1Id = random_bytes(16);
        $cred2Id = random_bytes(16);

        $source1 = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $cred1Id,
            type: 'public-key',
            transports: [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::v4(),
            credentialPublicKey: random_bytes(77),
            userHandle: (string) $user1->id,
            counter: 0,
        );

        $source2 = PublicKeyCredentialSource::create(
            publicKeyCredentialId: $cred2Id,
            type: 'public-key',
            transports: [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::v4(),
            credentialPublicKey: random_bytes(77),
            userHandle: (string) $user2->id,
            counter: 0,
        );

        MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $user1->id,
            'type' => 'webauthn',
            'name' => 'User 1 Key',
            'secret' => $this->serializer->toJson($source1),
            'created_at' => now(),
        ]);

        MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $user2->id,
            'type' => 'webauthn',
            'name' => 'User 2 Key',
            'secret' => $this->serializer->toJson($source2),
            'created_at' => now(),
        ]);

        // Act
        $result = $this->action->execute($user1, asJson: false);

        // Assert
        expect($result->allowCredentials)->toHaveCount(1)
            ->and($result->allowCredentials[0]->id)->toBe($cred1Id)
            ->and($result->allowCredentials[0]->id)->not->toBe($cred2Id);
    });

    test('handles user with large number of credentials', function (): void {
        // Arrange - Create 10 credentials for the user
        $credentialIds = [];

        for ($i = 0; $i < 10; ++$i) {
            $credId = random_bytes(16);
            $credentialIds[] = $credId;

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
                'type' => $i % 2 === 0 ? 'webauthn' : 'passkey',
                'name' => 'Key '.$i,
                'secret' => $this->serializer->toJson($source),
                'created_at' => now(),
            ]);
        }

        // Act
        $result = $this->action->execute($this->user, asJson: false);

        // Assert
        expect($result->allowCredentials)->toHaveCount(10);

        // Verify all credential IDs are present
        $resultIds = array_map(fn ($cred) => $cred->id, $result->allowCredentials);

        foreach ($credentialIds as $credId) {
            expect($resultIds)->toContain($credId);
        }
    });
});
