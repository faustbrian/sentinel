<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\Events\TotpDisabled;
use Cline\Sentinel\Events\WebAuthnCredentialRemoved;
use Cline\Sentinel\Facades\Sentinel;
use Illuminate\Support\Facades\Event;

beforeEach(function (): void {
    $this->user = createUser();
});

describe('hasMultiFactorAuth', function (): void {
    test('returns false when user has no credentials', function (): void {
        $result = Sentinel::for($this->user)->hasMultiFactorAuth();

        expect($result)->toBeFalse();
    });

    test('returns true when user has TOTP credential', function (): void {
        createTotpCredential($this->user);

        $result = Sentinel::for($this->user)->hasMultiFactorAuth();

        expect($result)->toBeTrue();
    });

    test('returns true when user has WebAuthn credential', function (): void {
        createWebAuthnCredential($this->user);

        $result = Sentinel::for($this->user)->hasMultiFactorAuth();

        expect($result)->toBeTrue();
    });

    test('returns true when user has multiple credentials', function (): void {
        createTotpCredential($this->user);
        createWebAuthnCredential($this->user);

        $result = Sentinel::for($this->user)->hasMultiFactorAuth();

        expect($result)->toBeTrue();
    });
});

describe('hasTotpEnabled', function (): void {
    test('returns false when user has no TOTP credential', function (): void {
        $result = Sentinel::for($this->user)->hasTotpEnabled();

        expect($result)->toBeFalse();
    });

    test('returns false when user has only WebAuthn credential', function (): void {
        createWebAuthnCredential($this->user);

        $result = Sentinel::for($this->user)->hasTotpEnabled();

        expect($result)->toBeFalse();
    });

    test('returns true when user has TOTP credential', function (): void {
        createTotpCredential($this->user);

        $result = Sentinel::for($this->user)->hasTotpEnabled();

        expect($result)->toBeTrue();
    });
});

describe('hasWebAuthnEnabled', function (): void {
    test('returns false when user has no WebAuthn credentials', function (): void {
        $result = Sentinel::for($this->user)->hasWebAuthnEnabled();

        expect($result)->toBeFalse();
    });

    test('returns false when user has only TOTP credential', function (): void {
        createTotpCredential($this->user);

        $result = Sentinel::for($this->user)->hasWebAuthnEnabled();

        expect($result)->toBeFalse();
    });

    test('returns true when user has one WebAuthn credential', function (): void {
        createWebAuthnCredential($this->user);

        $result = Sentinel::for($this->user)->hasWebAuthnEnabled();

        expect($result)->toBeTrue();
    });

    test('returns true when user has multiple WebAuthn credentials', function (): void {
        createWebAuthnCredential($this->user, 'Security Key 1');
        createWebAuthnCredential($this->user, 'Security Key 2');

        $result = Sentinel::for($this->user)->hasWebAuthnEnabled();

        expect($result)->toBeTrue();
    });
});

describe('hasRecoveryCodes', function (): void {
    test('returns false when user has no recovery codes', function (): void {
        $result = Sentinel::for($this->user)->hasRecoveryCodes();

        expect($result)->toBeFalse();
    });

    test('returns true when user has unused recovery codes', function (): void {
        createRecoveryCode($this->user, 'AAAAA-BBBBB');

        $result = Sentinel::for($this->user)->hasRecoveryCodes();

        expect($result)->toBeTrue();
    });

    test('returns true when user has multiple unused recovery codes', function (): void {
        createRecoveryCode($this->user, 'AAAAA-BBBBB');
        createRecoveryCode($this->user, 'CCCCC-DDDDD');

        $result = Sentinel::for($this->user)->hasRecoveryCodes();

        expect($result)->toBeTrue();
    });

    test('returns false when all recovery codes are used', function (): void {
        $code = createRecoveryCode($this->user, 'AAAAA-BBBBB');
        $code->update(['used_at' => now()]);

        $result = Sentinel::for($this->user)->hasRecoveryCodes();

        expect($result)->toBeFalse();
    });

    test('returns true when user has mix of used and unused recovery codes', function (): void {
        $usedCode = createRecoveryCode($this->user, 'AAAAA-BBBBB');
        $usedCode->update(['used_at' => now()]);
        createRecoveryCode($this->user, 'CCCCC-DDDDD');

        $result = Sentinel::for($this->user)->hasRecoveryCodes();

        expect($result)->toBeTrue();
    });
});

describe('getTotpCredential', function (): void {
    test('returns null when user has no TOTP credential', function (): void {
        $result = Sentinel::for($this->user)->getTotpCredential();

        expect($result)->toBeNull();
    });

    test('returns null when user has only WebAuthn credential', function (): void {
        createWebAuthnCredential($this->user);

        $result = Sentinel::for($this->user)->getTotpCredential();

        expect($result)->toBeNull();
    });

    test('returns TOTP credential when user has one', function (): void {
        $credential = createTotpCredential($this->user);

        $result = Sentinel::for($this->user)->getTotpCredential();

        expect($result)->toBeInstanceOf(MultiFactorCredential::class)
            ->and($result->id)->toBe($credential->id)
            ->and($result->type)->toBe('totp');
    });

    test('returns TOTP credential when user has both TOTP and WebAuthn', function (): void {
        $totpCredential = createTotpCredential($this->user);
        createWebAuthnCredential($this->user);

        $result = Sentinel::for($this->user)->getTotpCredential();

        expect($result)->toBeInstanceOf(MultiFactorCredential::class)
            ->and($result->id)->toBe($totpCredential->id)
            ->and($result->type)->toBe('totp');
    });
});

describe('getWebAuthnCredentials', function (): void {
    test('returns empty collection when user has no WebAuthn credentials', function (): void {
        $result = Sentinel::for($this->user)->getWebAuthnCredentials();

        expect($result)->toBeCollection()
            ->toHaveCount(0);
    });

    test('returns empty collection when user has only TOTP credential', function (): void {
        createTotpCredential($this->user);

        $result = Sentinel::for($this->user)->getWebAuthnCredentials();

        expect($result)->toBeCollection()
            ->toHaveCount(0);
    });

    test('returns collection with one credential when user has one WebAuthn credential', function (): void {
        $credential = createWebAuthnCredential($this->user);

        $result = Sentinel::for($this->user)->getWebAuthnCredentials();

        expect($result)->toBeCollection()
            ->toHaveCount(1)
            ->first()->toBeInstanceOf(MultiFactorCredential::class)
            ->and($result->first()->id)->toBe($credential->id)
            ->and($result->first()->type)->toBe('webauthn');
    });

    test('returns collection with multiple credentials when user has multiple WebAuthn credentials', function (): void {
        $credential1 = createWebAuthnCredential($this->user, 'Security Key 1');
        $credential2 = createWebAuthnCredential($this->user, 'Security Key 2');

        $result = Sentinel::for($this->user)->getWebAuthnCredentials();

        expect($result)->toBeCollection()
            ->toHaveCount(2)
            ->each->toBeInstanceOf(MultiFactorCredential::class)
            ->and($result->pluck('id')->toArray())->toContain($credential1->id, $credential2->id)
            ->and($result->pluck('type')->unique()->toArray())->toBe(['webauthn']);
    });

    test('returns only WebAuthn credentials when user has both TOTP and WebAuthn', function (): void {
        createTotpCredential($this->user);
        $webAuthnCredential = createWebAuthnCredential($this->user);

        $result = Sentinel::for($this->user)->getWebAuthnCredentials();

        expect($result)->toBeCollection()
            ->toHaveCount(1)
            ->first()->toBeInstanceOf(MultiFactorCredential::class)
            ->and($result->first()->id)->toBe($webAuthnCredential->id)
            ->and($result->first()->type)->toBe('webauthn');
    });
});

describe('remainingRecoveryCodes', function (): void {
    test('returns zero when user has no recovery codes', function (): void {
        $result = Sentinel::for($this->user)->remainingRecoveryCodes();

        expect($result)->toBe(0);
    });

    test('returns correct count when user has unused recovery codes', function (): void {
        Sentinel::recoveryCodes()->generate($this->user);

        $result = Sentinel::for($this->user)->remainingRecoveryCodes();

        expect($result)->toBe(8);
    });

    test('returns correct count after using some recovery codes', function (): void {
        $codes = Sentinel::recoveryCodes()->generate($this->user);
        Sentinel::recoveryCodes()->verify($this->user, $codes[0]);
        Sentinel::recoveryCodes()->verify($this->user, $codes[1]);

        $result = Sentinel::for($this->user)->remainingRecoveryCodes();

        expect($result)->toBe(6);
    });

    test('returns zero when all recovery codes are used', function (): void {
        $codes = Sentinel::recoveryCodes()->generate($this->user);

        foreach ($codes as $code) {
            Sentinel::recoveryCodes()->verify($this->user, $code);
        }

        $result = Sentinel::for($this->user)->remainingRecoveryCodes();

        expect($result)->toBe(0);
    });
});

describe('disableAllMfa', function (): void {
    test('removes TOTP credential when present', function (): void {
        Event::fake();

        createTotpCredential($this->user);

        Sentinel::for($this->user)->disableAllMfa();

        expect(Sentinel::for($this->user)->hasTotpEnabled())->toBeFalse()
            ->and(MultiFactorCredential::query()->where('user_id', $this->user->id)->where('type', 'totp')->exists())->toBeFalse();

        Event::assertDispatched(TotpDisabled::class);
    });

    test('removes WebAuthn credentials when present', function (): void {
        Event::fake();

        createWebAuthnCredential($this->user, 'Security Key 1');
        createWebAuthnCredential($this->user, 'Security Key 2');

        Sentinel::for($this->user)->disableAllMfa();

        expect(Sentinel::for($this->user)->hasWebAuthnEnabled())->toBeFalse()
            ->and(MultiFactorCredential::query()->where('user_id', $this->user->id)->where('type', 'webauthn')->count())->toBe(0);

        Event::assertDispatched(WebAuthnCredentialRemoved::class, 2);
    });

    test('removes recovery codes when present', function (): void {
        Sentinel::recoveryCodes()->generate($this->user);

        Sentinel::for($this->user)->disableAllMfa();

        expect(Sentinel::for($this->user)->hasRecoveryCodes())->toBeFalse()
            ->and(Sentinel::for($this->user)->remainingRecoveryCodes())->toBe(0);
    });

    test('removes all MFA methods when multiple are present', function (): void {
        Event::fake();

        createTotpCredential($this->user);
        createWebAuthnCredential($this->user);
        Sentinel::recoveryCodes()->generate($this->user);

        Sentinel::for($this->user)->disableAllMfa();

        expect(Sentinel::for($this->user)->hasMultiFactorAuth())->toBeFalse()
            ->and(Sentinel::for($this->user)->hasTotpEnabled())->toBeFalse()
            ->and(Sentinel::for($this->user)->hasWebAuthnEnabled())->toBeFalse()
            ->and(Sentinel::for($this->user)->hasRecoveryCodes())->toBeFalse();

        Event::assertDispatched(TotpDisabled::class);
        Event::assertDispatched(WebAuthnCredentialRemoved::class);
    });

    test('completes successfully when user has no MFA methods', function (): void {
        Event::fake();

        Sentinel::for($this->user)->disableAllMfa();

        expect(Sentinel::for($this->user)->hasMultiFactorAuth())->toBeFalse();

        // TotpDisabled event is always fired even when no TOTP exists
        Event::assertDispatched(TotpDisabled::class);
        Event::assertNotDispatched(WebAuthnCredentialRemoved::class);
    });
});
