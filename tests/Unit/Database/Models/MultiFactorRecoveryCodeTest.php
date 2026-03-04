<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Database\Models\MultiFactorRecoveryCode;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Date;
use Tests\Fixtures\User;

describe('MultiFactorRecoveryCode Model', function (): void {
    beforeEach(function (): void {
        $this->user = createUser();
    });

    describe('UUID Generation', function (): void {
        test('generates UUID as primary key', function (): void {
            // Arrange & Act
            $recoveryCode = createRecoveryCode($this->user);

            // Assert
            expect($recoveryCode->id)
                ->toBeString()
                ->toMatch('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i');
        });

        test('generates unique UUIDs for multiple codes', function (): void {
            // Arrange & Act
            $code1 = createRecoveryCode($this->user, 'CODE1-11111');
            $code2 = createRecoveryCode($this->user, 'CODE2-22222');

            // Assert
            expect($code1->id)->not->toBe($code2->id);
        });
    });

    describe('Fillable Attributes', function (): void {
        test('allows mass assignment of user_id', function (): void {
            // Arrange
            $attributes = [
                'user_id' => $this->user->id,
                'code_hash' => bcrypt('TEST-CODE'),
                'created_at' => now(),
            ];

            // Act
            $recoveryCode = MultiFactorRecoveryCode::query()->create($attributes);

            // Assert
            expect($recoveryCode->user_id)->toBe($this->user->id);
        });

        test('allows mass assignment of code_hash', function (): void {
            // Arrange
            $codeHash = bcrypt('TEST-CODE');
            $attributes = [
                'user_id' => $this->user->id,
                'code_hash' => $codeHash,
                'created_at' => now(),
            ];

            // Act
            $recoveryCode = MultiFactorRecoveryCode::query()->create($attributes);

            // Assert
            expect($recoveryCode->code_hash)->toBe($codeHash);
        });

        test('allows mass assignment of used_at', function (): void {
            // Arrange
            $usedAt = now();
            $attributes = [
                'user_id' => $this->user->id,
                'code_hash' => bcrypt('TEST-CODE'),
                'used_at' => $usedAt,
                'created_at' => now(),
            ];

            // Act
            $recoveryCode = MultiFactorRecoveryCode::query()->create($attributes);

            // Assert
            expect($recoveryCode->used_at)
                ->toBeInstanceOf(Carbon::class)
                ->and($recoveryCode->used_at->timestamp)->toBe($usedAt->timestamp);
        });

        test('allows mass assignment of created_at', function (): void {
            // Arrange
            $createdAt = now()->subDays(5);
            $attributes = [
                'user_id' => $this->user->id,
                'code_hash' => bcrypt('TEST-CODE'),
                'created_at' => $createdAt,
            ];

            // Act
            $recoveryCode = MultiFactorRecoveryCode::query()->create($attributes);

            // Assert
            expect($recoveryCode->created_at)
                ->toBeInstanceOf(Carbon::class)
                ->and($recoveryCode->created_at->timestamp)->toBe($createdAt->timestamp);
        });
    });

    describe('Code Hash Storage', function (): void {
        test('stores code_hash as bcrypt hash', function (): void {
            // Arrange
            $plainCode = 'PLAIN-12345';

            // Act
            $recoveryCode = createRecoveryCode($this->user, $plainCode);

            // Assert
            expect($recoveryCode->code_hash)
                ->toBeString()
                ->toStartWith('$2y$') // bcrypt prefix
                ->and(password_verify($plainCode, $recoveryCode->code_hash))->toBeTrue();
        });

        test('stores different hashes for different codes', function (): void {
            // Arrange & Act
            $code1 = createRecoveryCode($this->user, 'CODE1-11111');
            $code2 = createRecoveryCode($this->user, 'CODE2-22222');

            // Assert
            expect($code1->code_hash)->not->toBe($code2->code_hash);
        });
    });

    describe('Datetime Casting', function (): void {
        test('casts used_at to Carbon instance', function (): void {
            // Arrange
            $usedAt = now();
            $recoveryCode = createRecoveryCode($this->user);

            // Act
            $recoveryCode->update(['used_at' => $usedAt]);

            // Assert
            expect($recoveryCode->fresh()->used_at)
                ->toBeInstanceOf(Carbon::class)
                ->and($recoveryCode->fresh()->used_at->timestamp)->toBe($usedAt->timestamp);
        });

        test('casts created_at to Carbon instance', function (): void {
            // Arrange & Act
            $recoveryCode = createRecoveryCode($this->user);

            // Assert
            expect($recoveryCode->created_at)->toBeInstanceOf(Carbon::class);
        });

        test('returns null for unused code used_at', function (): void {
            // Arrange & Act
            $recoveryCode = createRecoveryCode($this->user);

            // Assert
            expect($recoveryCode->used_at)->toBeNull();
        });

        test('preserves Carbon datetime precision for used_at', function (): void {
            // Arrange
            $usedAt = Date::parse('2025-01-15 14:30:45');
            $recoveryCode = createRecoveryCode($this->user);

            // Act
            $recoveryCode->update(['used_at' => $usedAt]);

            // Assert
            $fresh = $recoveryCode->fresh();
            expect($fresh->used_at->year)->toBe(2_025)
                ->and($fresh->used_at->month)->toBe(1)
                ->and($fresh->used_at->day)->toBe(15)
                ->and($fresh->used_at->hour)->toBe(14)
                ->and($fresh->used_at->minute)->toBe(30)
                ->and($fresh->used_at->second)->toBe(45);
        });

        test('preserves Carbon datetime precision for created_at', function (): void {
            // Arrange
            $createdAt = Date::parse('2025-01-10 09:15:30');

            // Act
            $recoveryCode = createRecoveryCode($this->user);
            $recoveryCode->update(['created_at' => $createdAt]);

            // Assert
            $fresh = $recoveryCode->fresh();
            expect($fresh->created_at->year)->toBe(2_025)
                ->and($fresh->created_at->month)->toBe(1)
                ->and($fresh->created_at->day)->toBe(10)
                ->and($fresh->created_at->hour)->toBe(9)
                ->and($fresh->created_at->minute)->toBe(15)
                ->and($fresh->created_at->second)->toBe(30);
        });
    });

    describe('User Relationship', function (): void {
        test('returns BelongsTo relationship', function (): void {
            // Arrange
            $recoveryCode = createRecoveryCode($this->user);

            // Act
            $relationship = $recoveryCode->user();

            // Assert
            expect($relationship)->toBeInstanceOf(BelongsTo::class);
        });

        test('retrieves correct user instance', function (): void {
            // Arrange
            $recoveryCode = createRecoveryCode($this->user);

            // Act
            $relatedUser = $recoveryCode->user;

            // Assert
            expect($relatedUser)
                ->toBeInstanceOf(User::class)
                ->and($relatedUser->id)->toBe($this->user->id)
                ->and($relatedUser->email)->toBe($this->user->email);
        });

        test('uses configured auth model from config', function (): void {
            // Arrange
            $recoveryCode = createRecoveryCode($this->user);

            // Act
            $relationship = $recoveryCode->user();

            // Assert
            expect($relationship->getRelated())->toBeInstanceOf(User::class);
        });

        test('relationship works with multiple users', function (): void {
            // Arrange
            $user1 = createUser('user1@example.com');
            $user2 = createUser('user2@example.com');
            $code1 = createRecoveryCode($user1, 'CODE1-11111');
            $code2 = createRecoveryCode($user2, 'CODE2-22222');

            // Act
            $retrievedUser1 = $code1->user;
            $retrievedUser2 = $code2->user;

            // Assert
            expect($retrievedUser1->id)->toBe($user1->id)
                ->and($retrievedUser2->id)->toBe($user2->id)
                ->and($retrievedUser1->id)->not->toBe($retrievedUser2->id);
        });

        test('eager loads user relationship', function (): void {
            // Arrange
            $recoveryCode = createRecoveryCode($this->user);

            // Act
            $loadedCode = MultiFactorRecoveryCode::query()
                ->with('user')
                ->find($recoveryCode->id);

            // Assert
            expect($loadedCode->relationLoaded('user'))->toBeTrue()
                ->and($loadedCode->user)->toBeInstanceOf(User::class)
                ->and($loadedCode->user->id)->toBe($this->user->id);
        });

        test('user relationship reads model from config', function (): void {
            // Arrange
            $recoveryCode = createRecoveryCode($this->user);
            $configuredModel = config('auth.providers.users.model');

            // Act
            $relationship = $recoveryCode->user();
            $relatedModel = $relationship->getRelated();

            // Assert
            expect($configuredModel)->toBe(User::class)
                ->and($relatedModel)->toBeInstanceOf($configuredModel);
        });

        test('user relationship foreign key matches user_id', function (): void {
            // Arrange
            $recoveryCode = createRecoveryCode($this->user);

            // Act
            $relationship = $recoveryCode->user();

            // Assert
            expect($relationship->getForeignKeyName())->toBe('user_id')
                ->and($relationship->getOwnerKeyName())->toBe('id');
        });
    });

    describe('Single-Use Enforcement', function (): void {
        test('marks code as used with timestamp', function (): void {
            // Arrange
            $recoveryCode = createRecoveryCode($this->user);
            expect($recoveryCode->used_at)->toBeNull();

            // Act
            $usedAt = now();
            $recoveryCode->update(['used_at' => $usedAt]);

            // Assert
            expect($recoveryCode->fresh()->used_at)
                ->toBeInstanceOf(Carbon::class)
                ->and($recoveryCode->fresh()->used_at->timestamp)->toBe($usedAt->timestamp);
        });

        test('distinguishes between used and unused codes', function (): void {
            // Arrange
            $usedCode = createRecoveryCode($this->user, 'USED-12345');
            $unusedCode = createRecoveryCode($this->user, 'UNUSED-67890');

            // Act
            $usedCode->update(['used_at' => now()]);

            // Assert
            expect($usedCode->fresh()->used_at)->not->toBeNull()
                ->and($unusedCode->fresh()->used_at)->toBeNull();
        });

        test('queries unused codes correctly', function (): void {
            // Arrange
            createRecoveryCode($this->user, 'USED-11111')->update(['used_at' => now()]);
            createRecoveryCode($this->user, 'UNUSED-22222');
            createRecoveryCode($this->user, 'UNUSED-33333');

            // Act
            $unusedCodes = MultiFactorRecoveryCode::query()
                ->where('user_id', $this->user->id)
                ->whereNull('used_at')
                ->get();

            // Assert
            expect($unusedCodes)->toHaveCount(2);
        });

        test('queries used codes correctly', function (): void {
            // Arrange
            createRecoveryCode($this->user, 'USED-11111')->update(['used_at' => now()]);
            createRecoveryCode($this->user, 'USED-22222')->update(['used_at' => now()]);
            createRecoveryCode($this->user, 'UNUSED-33333');

            // Act
            $usedCodes = MultiFactorRecoveryCode::query()
                ->where('user_id', $this->user->id)
                ->whereNotNull('used_at')
                ->get();

            // Assert
            expect($usedCodes)->toHaveCount(2);
        });
    });

    describe('Timestamp Management', function (): void {
        test('disables automatic timestamp management', function (): void {
            // Arrange
            $recoveryCode = new MultiFactorRecoveryCode();

            // Act & Assert
            expect($recoveryCode->timestamps)->toBeFalse();
        });

        test('does not set updated_at timestamp', function (): void {
            // Arrange
            $recoveryCode = createRecoveryCode($this->user);

            // Act
            $recoveryCode->update(['used_at' => now()]);

            // Assert
            expect($recoveryCode->fresh()->updated_at)->toBeNull();
        });

        test('manually manages created_at timestamp', function (): void {
            // Arrange
            $customCreatedAt = now()->subDays(10);

            // Act
            $recoveryCode = MultiFactorRecoveryCode::query()->create([
                'user_id' => $this->user->id,
                'code_hash' => bcrypt('TEST-CODE'),
                'created_at' => $customCreatedAt,
            ]);

            // Assert
            expect($recoveryCode->created_at->timestamp)->toBe($customCreatedAt->timestamp);
        });
    });

    describe('Table Configuration', function (): void {
        test('uses correct table name', function (): void {
            // Arrange
            $recoveryCode = new MultiFactorRecoveryCode();

            // Act & Assert
            expect($recoveryCode->getTable())->toBe('multi_factor_recovery_codes');
        });
    });

    describe('Model Attributes', function (): void {
        test('retrieves all fillable attributes correctly', function (): void {
            // Arrange
            $userId = $this->user->id;
            $codeHash = bcrypt('FULL-12345');
            $usedAt = now()->subHours(2);
            $createdAt = now()->subDays(7);

            // Act
            $recoveryCode = MultiFactorRecoveryCode::query()->create([
                'user_id' => $userId,
                'code_hash' => $codeHash,
                'used_at' => $usedAt,
                'created_at' => $createdAt,
            ]);

            // Assert
            $fresh = $recoveryCode->fresh();
            expect($fresh->user_id)->toBe($userId)
                ->and($fresh->code_hash)->toBe($codeHash)
                ->and($fresh->used_at->timestamp)->toBe($usedAt->timestamp)
                ->and($fresh->created_at->timestamp)->toBe($createdAt->timestamp);
        });
    });
});
