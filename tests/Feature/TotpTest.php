<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\Events\MultiFactorChallengeFailed;
use Cline\Sentinel\Events\TotpDisabled;
use Cline\Sentinel\Events\TotpEnabled;
use Cline\Sentinel\Exceptions\TotpSetupNotInitializedException;
use Cline\Sentinel\Facades\Sentinel;
use Illuminate\Support\Facades\Event;
use PragmaRX\Google2FA\Google2FA;

beforeEach(function (): void {
    $this->user = createUser();
});

test('can begin TOTP setup', function (): void {
    $setup = Sentinel::totp()->beginSetup($this->user);

    expect($setup->getSecret())->toBeString()
        ->and($setup->getProvisioningUri())->toContain('otpauth://totp/')
        ->and($setup->getQrCodeSvg())->toContain('<svg')
        ->and($setup->getQrCodeDataUri())->toStartWith('data:image/svg+xml;base64,');
});

test('can confirm TOTP setup with valid code', function (): void {
    Event::fake();

    $setup = Sentinel::totp()->beginSetup($this->user);

    // Generate valid TOTP code
    $google2fa = new Google2FA();
    $validCode = $google2fa->getCurrentOtp($setup->getSecret());

    $result = Sentinel::totp()->confirmSetup($this->user, $validCode);

    expect($result)->toBeTrue()
        ->and(MultiFactorCredential::query()->where('user_id', $this->user->id)->where('type', 'totp')->exists())->toBeTrue();

    Event::assertDispatched(TotpEnabled::class);
});

test('fails to confirm TOTP setup with invalid code', function (): void {
    Event::fake();

    Sentinel::totp()->beginSetup($this->user);

    $result = Sentinel::totp()->confirmSetup($this->user, '000000');

    expect($result)->toBeFalse();

    Event::assertDispatched(MultiFactorChallengeFailed::class);
});

test('throws exception when confirming setup without beginning', function (): void {
    Sentinel::totp()->confirmSetup($this->user, '123456');
})->throws(TotpSetupNotInitializedException::class);

test('can verify TOTP code', function (): void {
    $secret = 'JBSWY3DPEHPK3PXP';
    createTotpCredential($this->user, $secret);

    $google2fa = new Google2FA();
    $validCode = $google2fa->getCurrentOtp($secret);

    $result = Sentinel::totp()->verify($this->user, $validCode);

    expect($result)->toBeTrue();
});

test('fails to verify invalid TOTP code', function (): void {
    Event::fake();

    createTotpCredential($this->user);

    $result = Sentinel::totp()->verify($this->user, '000000');

    expect($result)->toBeFalse();

    Event::assertDispatched(MultiFactorChallengeFailed::class);
});

test('can disable TOTP', function (): void {
    Event::fake();

    createTotpCredential($this->user);

    Sentinel::totp()->disable($this->user);

    expect(MultiFactorCredential::query()->where('user_id', $this->user->id)->where('type', 'totp')->exists())->toBeFalse();

    Event::assertDispatched(TotpDisabled::class);
});

test('can cancel TOTP setup', function (): void {
    Sentinel::totp()->beginSetup($this->user);
    Sentinel::totp()->cancelSetup();

    // Confirm should now fail
    expect(fn () => Sentinel::totp()->confirmSetup($this->user, '123456'))
        ->toThrow(TotpSetupNotInitializedException::class);
});
