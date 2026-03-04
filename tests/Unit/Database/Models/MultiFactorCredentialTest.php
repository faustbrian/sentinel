<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\Fixtures\User;

beforeEach(function (): void {
    $this->user = createUser();
});

describe('Model Attributes', function (): void {
    test('has correct table name', function (): void {
        // Arrange
        $credential = new MultiFactorCredential();

        // Act
        $tableName = $credential->getTable();

        // Assert
        expect($tableName)->toBe('multi_factor_credentials');
    });

    test('has timestamps disabled', function (): void {
        // Arrange
        $credential = new MultiFactorCredential();

        // Act
        $timestamps = $credential->timestamps;

        // Assert
        expect($timestamps)->toBeFalse();
    });

    test('has correct fillable attributes', function (): void {
        // Arrange
        $credential = new MultiFactorCredential();

        // Act
        $fillable = $credential->getFillable();

        // Assert
        expect($fillable)->toBe([
            'user_id',
            'type',
            'name',
            'secret',
            'metadata',
            'last_used_at',
            'created_at',
        ]);
    });

    test('uses UUID as primary key', function (): void {
        // Arrange
        $credential = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => 'Test Credential',
            'secret' => 'test-secret',
            'created_at' => now(),
        ]);

        // Act
        $id = $credential->id;

        // Assert
        expect($id)->toBeString()
            ->and(Str::isUuid($id))->toBeTrue();
    });
});

describe('Attribute Casting', function (): void {
    test('casts secret as encrypted', function (): void {
        // Arrange
        $plainSecret = 'JBSWY3DPEHPK3PXP';

        // Act
        $credential = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => 'Authenticator App',
            'secret' => $plainSecret,
            'created_at' => now(),
        ]);

        // Assert
        // Verify the secret is encrypted in the database
        $rawSecret = DB::table('multi_factor_credentials')
            ->where('id', $credential->id)
            ->value('secret');

        expect($rawSecret)->not->toBe($plainSecret)
            ->and($credential->secret)->toBe($plainSecret);
    });

    test('casts metadata as array', function (): void {
        // Arrange
        $metadata = ['counter' => 5, 'device' => 'YubiKey'];

        // Act
        $credential = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'Security Key',
            'secret' => 'test-secret',
            'metadata' => $metadata,
            'created_at' => now(),
        ]);

        // Assert
        expect($credential->metadata)->toBeArray()
            ->toBe($metadata)
            ->and($credential->metadata['counter'])->toBe(5)
            ->and($credential->metadata['device'])->toBe('YubiKey');
    });

    test('casts last_used_at as datetime', function (): void {
        // Arrange
        $lastUsedAt = now()->subHours(2);

        // Act
        $credential = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => 'Authenticator App',
            'secret' => 'test-secret',
            'last_used_at' => $lastUsedAt,
            'created_at' => now(),
        ]);

        // Assert
        expect($credential->last_used_at)->toBeInstanceOf(Carbon::class)
            ->and($credential->last_used_at->toDateTimeString())->toBe($lastUsedAt->toDateTimeString());
    });

    test('casts created_at as datetime', function (): void {
        // Arrange
        $createdAt = now()->subDays(7);

        // Act
        $credential = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => 'Authenticator App',
            'secret' => 'test-secret',
            'created_at' => $createdAt,
        ]);

        // Assert
        expect($credential->created_at)->toBeInstanceOf(Carbon::class)
            ->and($credential->created_at->toDateTimeString())->toBe($createdAt->toDateTimeString());
    });

    test('handles null metadata gracefully', function (): void {
        // Arrange & Act
        $credential = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => 'Authenticator App',
            'secret' => 'test-secret',
            'metadata' => null,
            'created_at' => now(),
        ]);

        // Assert
        expect($credential->metadata)->toBeNull();
    });

    test('handles null last_used_at gracefully', function (): void {
        // Arrange & Act
        $credential = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => 'Authenticator App',
            'secret' => 'test-secret',
            'created_at' => now(),
        ]);

        // Assert
        expect($credential->last_used_at)->toBeNull();
    });
});

describe('User Relationship', function (): void {
    test('belongs to a user', function (): void {
        // Arrange
        $credential = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => 'Authenticator App',
            'secret' => 'test-secret',
            'created_at' => now(),
        ]);

        // Act
        $user = $credential->user;

        // Assert
        expect($user)->toBeInstanceOf(User::class)
            ->and($user->id)->toBe($this->user->id)
            ->and($user->email)->toBe($this->user->email)
            ->and($user->name)->toBe($this->user->name);
    });

    test('user relationship returns BelongsTo instance', function (): void {
        // Arrange
        $credential = new MultiFactorCredential();

        // Act
        $relationship = $credential->user();

        // Assert
        expect($relationship)->toBeInstanceOf(BelongsTo::class);
    });

    test('user relationship uses configured auth model', function (): void {
        // Arrange
        $credential = new MultiFactorCredential();

        // Act
        $relationship = $credential->user();

        // Assert
        expect($relationship->getRelated())->toBeInstanceOf(User::class);
    });
});

describe('TOTP Credential Creation', function (): void {
    test('can create TOTP credential with all attributes', function (): void {
        // Arrange
        $secret = 'JBSWY3DPEHPK3PXP';
        $createdAt = now();

        // Act
        $credential = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => 'Google Authenticator',
            'secret' => $secret,
            'created_at' => $createdAt,
        ]);

        // Assert
        expect($credential->user_id)->toBe($this->user->id)
            ->and($credential->type)->toBe('totp')
            ->and($credential->name)->toBe('Google Authenticator')
            ->and($credential->secret)->toBe($secret)
            ->and($credential->created_at->toDateTimeString())->toBe($createdAt->toDateTimeString())
            ->and($credential->last_used_at)->toBeNull()
            ->and($credential->metadata)->toBeNull();
    });

    test('can update last_used_at for TOTP credential', function (): void {
        // Arrange
        $credential = createTotpCredential($this->user);
        $lastUsedAt = now();

        // Act
        $credential->update(['last_used_at' => $lastUsedAt]);
        $credential->refresh();

        // Assert
        expect($credential->last_used_at)->toBeInstanceOf(Carbon::class)
            ->and($credential->last_used_at->toDateTimeString())->toBe($lastUsedAt->toDateTimeString());
    });
});

describe('WebAuthn Credential Creation', function (): void {
    test('can create WebAuthn credential with metadata', function (): void {
        // Arrange
        $publicKey = ['publicKey' => 'test-key-data', 'algorithm' => -7];
        $metadata = ['counter' => 0, 'aaguid' => 'test-aaguid', 'transports' => ['usb', 'nfc']];
        $createdAt = now();

        // Act
        $credential = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'YubiKey 5 NFC',
            'secret' => json_encode($publicKey),
            'metadata' => $metadata,
            'created_at' => $createdAt,
        ]);

        // Assert
        expect($credential->user_id)->toBe($this->user->id)
            ->and($credential->type)->toBe('webauthn')
            ->and($credential->name)->toBe('YubiKey 5 NFC')
            ->and($credential->secret)->toBe(json_encode($publicKey))
            ->and($credential->metadata)->toBe($metadata)
            ->and($credential->metadata['counter'])->toBe(0)
            ->and($credential->metadata['transports'])->toBe(['usb', 'nfc'])
            ->and($credential->created_at->toDateTimeString())->toBe($createdAt->toDateTimeString());
    });

    test('can increment counter in WebAuthn metadata', function (): void {
        // Arrange
        $credential = createWebAuthnCredential($this->user);
        $initialCounter = $credential->metadata['counter'];

        // Act
        $metadata = $credential->metadata;
        ++$metadata['counter'];
        $credential->update(['metadata' => $metadata]);
        $credential->refresh();

        // Assert
        expect($credential->metadata['counter'])->toBe($initialCounter + 1);
    });
});

describe('Mass Assignment', function (): void {
    test('allows mass assignment of all fillable attributes', function (): void {
        // Arrange
        $attributes = [
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => 'Test App',
            'secret' => 'test-secret',
            'metadata' => ['test' => 'data'],
            'last_used_at' => now(),
            'created_at' => now(),
        ];

        // Act
        $credential = new MultiFactorCredential($attributes);

        // Assert
        expect($credential->user_id)->toBe($attributes['user_id'])
            ->and($credential->type)->toBe($attributes['type'])
            ->and($credential->name)->toBe($attributes['name'])
            ->and($credential->secret)->toBe($attributes['secret'])
            ->and($credential->metadata)->toBe($attributes['metadata'])
            ->and($credential->last_used_at)->toBeInstanceOf(Carbon::class)
            ->and($credential->created_at)->toBeInstanceOf(Carbon::class);
    });
});

describe('Edge Cases', function (): void {
    test('handles empty string secret', function (): void {
        // Arrange & Act
        $credential = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => 'Test',
            'secret' => '',
            'created_at' => now(),
        ]);

        // Assert
        expect($credential->secret)->toBe('');
    });

    test('handles very long credential name', function (): void {
        // Arrange
        $longName = str_repeat('a', 255);

        // Act
        $credential = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => $longName,
            'secret' => 'test-secret',
            'created_at' => now(),
        ]);

        // Assert
        expect($credential->name)->toBe($longName)
            ->and(mb_strlen($credential->name))->toBe(255);
    });

    test('handles complex nested metadata', function (): void {
        // Arrange
        $complexMetadata = [
            'device' => [
                'type' => 'YubiKey',
                'version' => '5.2',
                'features' => ['nfc', 'usb-c', 'lightning'],
            ],
            'counters' => [
                'total_uses' => 42,
                'failed_attempts' => 0,
            ],
            'settings' => [
                'require_touch' => true,
                'timeout' => 30,
            ],
        ];

        // Act
        $credential = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'webauthn',
            'name' => 'Complex Key',
            'secret' => 'test-secret',
            'metadata' => $complexMetadata,
            'created_at' => now(),
        ]);

        // Assert
        expect($credential->metadata)->toBe($complexMetadata)
            ->and($credential->metadata['device']['features'])->toBe(['nfc', 'usb-c', 'lightning'])
            ->and($credential->metadata['counters']['total_uses'])->toBe(42)
            ->and($credential->metadata['settings']['require_touch'])->toBeTrue();
    });

    test('multiple credentials for same user maintain separate encrypted secrets', function (): void {
        // Arrange
        $secret1 = 'SECRET-ONE-12345';
        $secret2 = 'SECRET-TWO-67890';

        // Act
        $credential1 = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => 'App 1',
            'secret' => $secret1,
            'created_at' => now(),
        ]);

        $credential2 = MultiFactorCredential::query()->create([
            'user_id' => $this->user->id,
            'type' => 'totp',
            'name' => 'App 2',
            'secret' => $secret2,
            'created_at' => now(),
        ]);

        // Assert
        expect($credential1->secret)->toBe($secret1)
            ->and($credential2->secret)->toBe($secret2)
            ->and($credential1->secret)->not->toBe($credential2->secret);
    });

    test('can query credentials by type', function (): void {
        // Arrange
        createTotpCredential($this->user);
        createWebAuthnCredential($this->user);

        // Act
        $totpCredentials = MultiFactorCredential::query()
            ->where('user_id', $this->user->id)
            ->where('type', 'totp')
            ->get();

        $webAuthnCredentials = MultiFactorCredential::query()
            ->where('user_id', $this->user->id)
            ->where('type', 'webauthn')
            ->get();

        // Assert
        expect($totpCredentials)->toHaveCount(1)
            ->and($totpCredentials->first()->type)->toBe('totp')
            ->and($webAuthnCredentials)->toHaveCount(1)
            ->and($webAuthnCredentials->first()->type)->toBe('webauthn');
    });
});
