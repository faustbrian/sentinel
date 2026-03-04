<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\Database\Models\MultiFactorRecoveryCode;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Tests\Fixtures\User;

beforeEach(function (): void {
    $this->user = createUser();
});

describe('multiFactorCredentials relationship', function (): void {
    test('returns HasMany relationship', function (): void {
        // Arrange & Act
        $relationship = $this->user->multiFactorCredentials();

        // Assert
        expect($relationship)->toBeInstanceOf(HasMany::class)
            ->and($relationship->getRelated())->toBeInstanceOf(MultiFactorCredential::class);
    });

    test('returns empty collection when no credentials exist', function (): void {
        // Arrange & Act
        $credentials = $this->user->multiFactorCredentials;

        // Assert
        expect($credentials)->toBeEmpty();
    });

    test('returns all credentials for user', function (): void {
        // Arrange
        createTotpCredential($this->user);
        createWebAuthnCredential($this->user);

        // Act
        $credentials = $this->user->multiFactorCredentials;

        // Assert
        expect($credentials)->toHaveCount(2)
            ->and($credentials->pluck('type')->toArray())->toContain('totp', 'webauthn');
    });

    test('uses correct foreign key', function (): void {
        // Arrange & Act
        $relationship = $this->user->multiFactorCredentials();

        // Assert
        expect($relationship->getForeignKeyName())->toBe('user_id');
    });
});

describe('multiFactorRecoveryCodes relationship', function (): void {
    test('returns HasMany relationship', function (): void {
        // Arrange & Act
        $relationship = $this->user->multiFactorRecoveryCodes();

        // Assert
        expect($relationship)->toBeInstanceOf(HasMany::class)
            ->and($relationship->getRelated())->toBeInstanceOf(MultiFactorRecoveryCode::class);
    });

    test('returns empty collection when no recovery codes exist', function (): void {
        // Arrange & Act
        $recoveryCodes = $this->user->multiFactorRecoveryCodes;

        // Assert
        expect($recoveryCodes)->toBeEmpty();
    });

    test('returns all recovery codes for user', function (): void {
        // Arrange
        createRecoveryCode($this->user, 'AAAAA-AAAAA');
        createRecoveryCode($this->user, 'BBBBB-BBBBB');
        createRecoveryCode($this->user, 'CCCCC-CCCCC');

        // Act
        $recoveryCodes = $this->user->multiFactorRecoveryCodes;

        // Assert
        expect($recoveryCodes)->toHaveCount(3);
    });

    test('uses correct foreign key', function (): void {
        // Arrange & Act
        $relationship = $this->user->multiFactorRecoveryCodes();

        // Assert
        expect($relationship->getForeignKeyName())->toBe('user_id');
    });
});

describe('hasMfaEnabled method', function (): void {
    test('returns true when user has TOTP credential', function (): void {
        // Arrange
        createTotpCredential($this->user);

        // Act
        $result = $this->user->hasMultiFactorEnabled();

        // Assert
        expect($result)->toBeTrue();
    });

    test('returns true when user has WebAuthn credential', function (): void {
        // Arrange
        createWebAuthnCredential($this->user);

        // Act
        $result = $this->user->hasMultiFactorEnabled();

        // Assert
        expect($result)->toBeTrue();
    });

    test('returns true when user has multiple credentials', function (): void {
        // Arrange
        createTotpCredential($this->user);
        createWebAuthnCredential($this->user);

        // Act
        $result = $this->user->hasMultiFactorEnabled();

        // Assert
        expect($result)->toBeTrue();
    });

    test('returns false when user has no credentials', function (): void {
        // Arrange - user created without credentials

        // Act
        $result = $this->user->hasMultiFactorEnabled();

        // Assert
        expect($result)->toBeFalse();
    });

    test('returns false when user credentials are deleted', function (): void {
        // Arrange
        $credential = createTotpCredential($this->user);
        expect($this->user->hasMultiFactorEnabled())->toBeTrue();

        // Act
        $credential->delete();
        $this->user->refresh();

        // Assert
        expect($this->user->hasMultiFactorEnabled())->toBeFalse();
    });

    test('checks database for current state', function (): void {
        // Arrange
        expect($this->user->hasMultiFactorEnabled())->toBeFalse();

        // Act - Add credential after initial check
        createTotpCredential($this->user);

        // Assert - Should return true without refresh
        expect($this->user->hasMultiFactorEnabled())->toBeTrue();
    });
});

describe('edge cases', function (): void {
    test('handles multiple users with separate credentials', function (): void {
        // Arrange
        $user1 = $this->user;
        $user2 = User::query()->create([
            'id' => 2,
            'name' => 'Second User',
            'email' => 'second@example.com',
            'password' => bcrypt('password'),
        ]);

        createTotpCredential($user1);

        // Act & Assert
        expect($user1->hasMultiFactorEnabled())->toBeTrue()
            ->and($user2->hasMultiFactorEnabled())->toBeFalse()
            ->and($user1->multiFactorCredentials)->toHaveCount(1)
            ->and($user2->multiFactorCredentials)->toHaveCount(0);
    });

    test('relationships are isolated between users', function (): void {
        // Arrange
        $user1 = $this->user;
        $user2 = User::query()->create([
            'id' => 2,
            'name' => 'Second User',
            'email' => 'second@example.com',
            'password' => bcrypt('password'),
        ]);

        createTotpCredential($user1);
        createWebAuthnCredential($user1);
        createRecoveryCode($user1);

        createTotpCredential($user2);

        // Act & Assert
        expect($user1->multiFactorCredentials)->toHaveCount(2)
            ->and($user2->multiFactorCredentials)->toHaveCount(1)
            ->and($user1->multiFactorRecoveryCodes)->toHaveCount(1)
            ->and($user2->multiFactorRecoveryCodes)->toHaveCount(0);
    });
});
