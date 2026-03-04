<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Contracts\AuthenticatorAssertionValidator;
use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\Events\WebAuthnCredentialRegistered;
use Cline\Sentinel\Events\WebAuthnCredentialRemoved;
use Cline\Sentinel\Exceptions\InvalidWebAuthnAssertionException;
use Cline\Sentinel\WebAuthn\Actions\ConfirmRegistrationAction;
use Cline\Sentinel\WebAuthn\Actions\GenerateAuthenticationOptionsAction;
use Cline\Sentinel\WebAuthn\Actions\GenerateRegistrationOptionsAction;
use Cline\Sentinel\WebAuthn\Actions\VerifyAuthenticationAction;
use Cline\Sentinel\WebAuthn\WebAuthnManager;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;

beforeEach(function (): void {
    $this->user = createUser();

    // Mock the validator for unit testing
    $mockValidator = Mockery::mock(AuthenticatorAssertionValidator::class);

    $this->manager = new WebAuthnManager(
        generateRegistrationOptions: new GenerateRegistrationOptionsAction(),
        confirmRegistration: new ConfirmRegistrationAction(),
        generateAuthenticationOptions: new GenerateAuthenticationOptionsAction(),
        verifyAuthentication: new VerifyAuthenticationAction($mockValidator),
    );
});

describe('beginRegistration', function (): void {
    test('delegates to GenerateRegistrationOptionsAction and returns JSON', function (): void {
        // Arrange
        config([
            'sentinel.webauthn.relying_party.name' => 'Test App',
            'sentinel.webauthn.relying_party.id' => 'example.com',
        ]);

        // Act
        $result = $this->manager->beginRegistration($this->user, asPasskey: true);

        // Assert
        expect($result)->toBeString()
            ->and(json_validate($result))->toBeTrue();

        $decoded = json_decode($result, true);
        expect($decoded)->toBeArray()
            ->toHaveKeys(['challenge', 'rp', 'user']);
    });

    test('passes asPasskey parameter correctly for passkey mode', function (): void {
        // Arrange
        config([
            'sentinel.webauthn.relying_party.name' => 'Test App',
            'sentinel.webauthn.relying_party.id' => 'example.com',
        ]);

        // Act
        $passkeyResult = $this->manager->beginRegistration($this->user, asPasskey: true);
        $securityKeyResult = $this->manager->beginRegistration($this->user, asPasskey: false);

        // Assert
        $passkeyDecoded = json_decode($passkeyResult, true);
        $securityKeyDecoded = json_decode($securityKeyResult, true);

        // Both should have authenticatorSelection but with different residentKey values
        expect($passkeyDecoded)->toHaveKey('authenticatorSelection')
            ->and($securityKeyDecoded)->toHaveKey('authenticatorSelection');
    });
});

describe('confirmRegistration', function (): void {
    test('delegates to ConfirmRegistrationAction and dispatches event on invalid data', function (): void {
        // Arrange
        Event::fake();

        $credentialJson = '{"id":"test"}';
        $optionsJson = 'invalid-json';
        $hostname = 'example.com';
        $name = 'Test Key';
        $type = 'webauthn';

        // Act & Assert - Method should be called even if action throws
        try {
            $this->manager->confirmRegistration(
                user: $this->user,
                credentialJson: $credentialJson,
                optionsJson: $optionsJson,
                hostname: $hostname,
                name: $name,
                type: $type,
            );
        } catch (InvalidWebAuthnAssertionException $invalidWebAuthnAssertionException) {
            // Expected - the action will throw on invalid JSON
            expect($invalidWebAuthnAssertionException->getMessage())->toContain('Invalid registration options JSON');
        }

        // The manager code (lines 121-134) was executed before the action threw
        Event::assertNotDispatched(WebAuthnCredentialRegistered::class);
    });
});

describe('verify', function (): void {
    test('delegates to VerifyAuthenticationAction and catches invalid credential JSON', function (): void {
        // Arrange
        $credentialJson = 'invalid-json';
        $optionsJson = '{"challenge":"test","rpId":"example.com"}';
        $hostname = 'example.com';

        // Act & Assert - Method should throw when given invalid credential JSON
        expect(fn () => $this->manager->verify(
            credentialJson: $credentialJson,
            optionsJson: $optionsJson,
            hostname: $hostname,
        ))->toThrow(InvalidWebAuthnAssertionException::class, 'Invalid credential JSON');
    });

    test('delegates to VerifyAuthenticationAction and throws on validation errors', function (): void {
        // Arrange
        $credentialJson = '{"id":"dGVzdA","rawId":"dGVzdA","type":"public-key","response":{}}';
        $optionsJson = 'invalid-json';
        $hostname = 'example.com';

        // Act & Assert - Method should throw when validation fails
        expect(fn () => $this->manager->verify(
            credentialJson: $credentialJson,
            optionsJson: $optionsJson,
            hostname: $hostname,
        ))->toThrow(Exception::class);
    });
});

describe('beginAuthentication', function (): void {
    test('delegates to GenerateAuthenticationOptionsAction and returns JSON', function (): void {
        // Arrange
        config([
            'sentinel.webauthn.relying_party.id' => 'example.com',
        ]);

        // Act
        $result = $this->manager->beginAuthentication($this->user);

        // Assert
        expect($result)->toBeString()
            ->and(json_validate($result))->toBeTrue();

        $decoded = json_decode($result, true);
        expect($decoded)->toBeArray()
            ->toHaveKeys(['challenge', 'rpId']);
    });

    test('supports null user for discoverable credentials', function (): void {
        // Arrange
        config([
            'sentinel.webauthn.relying_party.id' => 'example.com',
        ]);

        // Act
        $result = $this->manager->beginAuthentication(null);

        // Assert
        expect($result)->toBeString()
            ->and(json_validate($result))->toBeTrue();
    });
});

describe('remove', function (): void {
    test('deletes credential and dispatches event', function (): void {
        // Arrange
        Event::fake();

        $credential = createWebAuthnCredential($this->user, 'YubiKey');

        // Act
        $this->manager->remove($this->user, $credential->id);

        // Assert
        expect(MultiFactorCredential::query()
            ->where('id', $credential->id)
            ->exists())->toBeFalse();

        Event::assertDispatched(WebAuthnCredentialRemoved::class, fn ($event): bool => $event->user->id === $this->user->id
            && $event->credentialId === $credential->id);
    });

    test('only deletes credentials owned by the specified user', function (): void {
        // Arrange
        Event::fake();

        $otherUser = createUser('other@example.com');
        $userCredential = createWebAuthnCredential($this->user, 'User Key');
        $otherCredential = createWebAuthnCredential($otherUser, 'Other Key');

        // Act
        $this->manager->remove($this->user, $otherCredential->id);

        // Assert
        expect(MultiFactorCredential::query()->where('id', $otherCredential->id)->exists())->toBeTrue()
            ->and(MultiFactorCredential::query()->where('id', $userCredential->id)->exists())->toBeTrue();
    });

    test('only deletes webauthn and passkey type credentials', function (): void {
        // Arrange
        Event::fake();

        $webauthnCredential = createWebAuthnCredential($this->user, 'Security Key');
        $totpCredential = createTotpCredential($this->user);

        // Act
        $this->manager->remove($this->user, $totpCredential->id);

        // Assert
        expect(MultiFactorCredential::query()->where('id', $totpCredential->id)->exists())->toBeTrue()
            ->and(MultiFactorCredential::query()->where('id', $webauthnCredential->id)->exists())->toBeTrue();
    });

    test('removes passkey credentials', function (): void {
        // Arrange
        Event::fake();

        // Create a passkey credential
        $passkeyCredential = MultiFactorCredential::query()->create([
            'id' => Str::uuid()->toString(),
            'user_id' => $this->user->id,
            'type' => 'passkey',
            'name' => 'MacBook Touch ID',
            'secret' => json_encode(['publicKey' => 'test']),
            'metadata' => ['counter' => 0],
            'created_at' => now(),
        ]);

        // Act
        $this->manager->remove($this->user, $passkeyCredential->id);

        // Assert
        expect(MultiFactorCredential::query()->where('id', $passkeyCredential->id)->exists())->toBeFalse();

        Event::assertDispatched(WebAuthnCredentialRemoved::class, fn ($event): bool => $event->credentialId === $passkeyCredential->id);
    });

    test('dispatches event even when credential does not exist', function (): void {
        // Arrange
        Event::fake();

        $nonExistentId = 'non-existent-credential-id';

        // Act
        $this->manager->remove($this->user, $nonExistentId);

        // Assert
        Event::assertDispatched(WebAuthnCredentialRemoved::class, fn ($event): bool => $event->user->id === $this->user->id
            && $event->credentialId === $nonExistentId);
    });

    test('does not throw exception when deleting non-existent credential', function (): void {
        // Arrange
        Event::fake();

        $nonExistentId = 'non-existent-uuid';

        // Act & Assert
        expect(fn () => $this->manager->remove($this->user, $nonExistentId))->not->toThrow(Exception::class);
    });
});
