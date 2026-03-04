<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Database\Models\MultiFactorRecoveryCode;
use Cline\Sentinel\Events\RecoveryCodesGenerated;
use Cline\Sentinel\Events\RecoveryCodeUsed;
use Cline\Sentinel\Facades\Sentinel;
use Illuminate\Support\Facades\Event;

beforeEach(function (): void {
    $this->user = createUser();
});

test('can generate recovery codes', function (): void {
    Event::fake();

    $codes = Sentinel::recoveryCodes()->generate($this->user);

    expect($codes)->toBeArray()
        ->toHaveCount(8)
        ->each->toMatch('/^[A-Z0-9]{5}-[A-Z0-9]{5}$/');

    $count = MultiFactorRecoveryCode::query()->where('user_id', $this->user->id)->count();
    expect($count)->toBe(8);

    Event::assertDispatched(RecoveryCodesGenerated::class);
});

test('generating new codes invalidates old ones', function (): void {
    $oldCodes = Sentinel::recoveryCodes()->generate($this->user);
    $newCodes = Sentinel::recoveryCodes()->generate($this->user);

    expect($newCodes)->not->toBe($oldCodes);

    $count = MultiFactorRecoveryCode::query()->where('user_id', $this->user->id)->count();
    expect($count)->toBe(8);
});

test('can verify and consume recovery code', function (): void {
    Event::fake();

    $codes = Sentinel::recoveryCodes()->generate($this->user);
    $code = $codes[0];

    $result = Sentinel::recoveryCodes()->verify($this->user, $code);

    expect($result)->toBeTrue();

    $remaining = Sentinel::recoveryCodes()->remaining($this->user);
    expect($remaining)->toBe(7);

    Event::assertDispatched(RecoveryCodeUsed::class);
});

test('recovery codes are one-time use', function (): void {
    $codes = Sentinel::recoveryCodes()->generate($this->user);
    $code = $codes[0];

    Sentinel::recoveryCodes()->verify($this->user, $code);

    $result = Sentinel::recoveryCodes()->verify($this->user, $code);

    expect($result)->toBeFalse();
});

test('fails to verify invalid recovery code', function (): void {
    Sentinel::recoveryCodes()->generate($this->user);

    $result = Sentinel::recoveryCodes()->verify($this->user, 'INVALID-CODE');

    expect($result)->toBeFalse();
});

test('can get remaining recovery codes count', function (): void {
    Sentinel::recoveryCodes()->generate($this->user);

    $remaining = Sentinel::recoveryCodes()->remaining($this->user);

    expect($remaining)->toBe(8);
});

test('can invalidate all recovery codes', function (): void {
    Sentinel::recoveryCodes()->generate($this->user);
    Sentinel::recoveryCodes()->invalidate($this->user);

    $count = MultiFactorRecoveryCode::query()->where('user_id', $this->user->id)->count();

    expect($count)->toBe(0);
});
