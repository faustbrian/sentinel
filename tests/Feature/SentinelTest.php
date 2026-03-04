<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Events\MultiFactorChallengeCompleted;
use Cline\Sentinel\Events\MultiFactorChallengeInitiated;
use Cline\Sentinel\Events\SudoModeEnabled;
use Cline\Sentinel\Facades\Sentinel;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Sleep;

beforeEach(function (): void {
    $this->user = createUser();
    $this->request = Request::create('/test');
    $this->request->setLaravelSession(session()->driver());
});

test('can initiate MFA challenge', function (): void {
    Event::fake();

    Sentinel::initiateMultiFactorChallenge($this->request, $this->user);

    expect(Sentinel::getChallengedUser($this->request))->toBeInstanceOf($this->user::class);

    Event::assertDispatched(MultiFactorChallengeInitiated::class);
});

test('can mark MFA as complete', function (): void {
    Event::fake();

    Sentinel::initiateMultiFactorChallenge($this->request, $this->user);
    Sentinel::markMultiFactorComplete($this->request);

    expect(Sentinel::hasMultiFactorCompleted($this->request))->toBeTrue();

    Event::assertDispatched(MultiFactorChallengeCompleted::class);
});

test('can clear MFA challenge', function (): void {
    Sentinel::initiateMultiFactorChallenge($this->request, $this->user);
    Sentinel::clearMultiFactorChallenge($this->request);

    expect(Sentinel::getChallengedUser($this->request))->toBeNull();
});

test('can enable sudo mode', function (): void {
    Event::fake();

    $this->request->setUserResolver(fn () => $this->user);

    Sentinel::enableSudoMode($this->request);

    expect(Sentinel::inSudoMode($this->request))->toBeTrue();

    Event::assertDispatched(SudoModeEnabled::class);
});

test('sudo mode expires after configured duration', function (): void {
    config(['sentinel.sudo_mode.duration' => 1]);

    Sentinel::enableSudoMode($this->request);

    expect(Sentinel::inSudoMode($this->request))->toBeTrue();

    Sleep::sleep(2);

    expect(Sentinel::inSudoMode($this->request))->toBeFalse();
});

test('can get sudo mode expiration time', function (): void {
    Sentinel::enableSudoMode($this->request);

    $expiresAt = Sentinel::sudoModeExpiresAt($this->request);

    expect($expiresAt)->toBeInstanceOf(Carbon::class);
});

test('can disable all MFA for user', function (): void {
    createTotpCredential($this->user);
    createWebAuthnCredential($this->user);
    Sentinel::recoveryCodes()->generate($this->user);

    Sentinel::disableAllMfa($this->user);

    expect(Sentinel::for($this->user)->hasMultiFactorAuth())->toBeFalse()
        ->and(Sentinel::for($this->user)->hasRecoveryCodes())->toBeFalse();
});

test('completing challenge without user in session does not throw exception', function (): void {
    // Clear any user from session
    session()->forget('multi_factor.user_id');

    // This should return early without throwing
    expect(fn () => Sentinel::completeChallenge($this->request))->not->toThrow(Exception::class);
});

test('sudo mode expiration returns null when not enabled', function (): void {
    // Don't enable sudo mode, just check expiration
    expect(Sentinel::sudoModeExpiresAt($this->request))->toBeNull();
});

test('TOTP verify returns false when user has no TOTP credential', function (): void {
    // User has no TOTP credential
    expect(Sentinel::totp()->verify($this->user, '123456'))->toBeFalse();
});
