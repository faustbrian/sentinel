<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\Database\Models\MultiFactorRecoveryCode;
use Illuminate\Support\Str;
use Tests\Fixtures\User;
use Tests\TestCase;

pest()->extend(TestCase::class)->in(__DIR__);

/**
 * Create a test user.
 */
function createUser(string $email = 'test@example.com'): User
{
    return User::query()->create([
        'id' => 1,
        'name' => 'Test User',
        'email' => $email,
        'password' => bcrypt('password'),
    ]);
}

/**
 * Create a TOTP credential for a user.
 */
function createTotpCredential(User $user, string $secret = 'JBSWY3DPEHPK3PXP'): MultiFactorCredential
{
    return MultiFactorCredential::query()->create([
        'id' => Str::uuid()->toString(),
        'user_id' => $user->id,
        'type' => 'totp',
        'name' => 'Authenticator App',
        'secret' => $secret,
        'created_at' => now(),
    ]);
}

/**
 * Create a WebAuthn credential for a user.
 */
function createWebAuthnCredential(User $user, string $name = 'Security Key'): MultiFactorCredential
{
    return MultiFactorCredential::query()->create([
        'id' => Str::uuid()->toString(),
        'user_id' => $user->id,
        'type' => 'webauthn',
        'name' => $name,
        'secret' => json_encode(['publicKey' => 'test']),
        'metadata' => ['counter' => 0],
        'created_at' => now(),
    ]);
}

/**
 * Create a recovery code for a user.
 */
function createRecoveryCode(User $user, string $code = 'XXXXX-XXXXX'): MultiFactorRecoveryCode
{
    return MultiFactorRecoveryCode::query()->create([
        'id' => Str::uuid()->toString(),
        'user_id' => $user->id,
        'code_hash' => bcrypt($code),
        'created_at' => now(),
    ]);
}
