<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Exceptions\InvalidRecoveryCodeException;
use Cline\Sentinel\Exceptions\InvalidTotpCodeException;
use Cline\Sentinel\Exceptions\InvalidWebAuthnAssertionException;
use Cline\Sentinel\Exceptions\MultiFactorNotEnabledException;
use Cline\Sentinel\Exceptions\SentinelException;
use Cline\Sentinel\Exceptions\TotpSetupNotInitializedException;
use Cline\Sentinel\Exceptions\WebAuthnSetupNotInitializedException;

describe('InvalidRecoveryCodeException', function (): void {
    test('can be instantiated', function (): void {
        $exception = InvalidRecoveryCodeException::invalidCode();

        expect($exception)->toBeInstanceOf(InvalidRecoveryCodeException::class);
    });

    test('has correct message', function (): void {
        $exception = InvalidRecoveryCodeException::invalidCode();

        expect($exception->getMessage())->toBe('The provided recovery code is invalid or has already been used.');
    });

    test('extends SentinelException', function (): void {
        $exception = InvalidRecoveryCodeException::invalidCode();

        expect($exception)->toBeInstanceOf(SentinelException::class);
    });
});

describe('InvalidTotpCodeException', function (): void {
    test('can be instantiated', function (): void {
        $exception = InvalidTotpCodeException::invalidCode();

        expect($exception)->toBeInstanceOf(InvalidTotpCodeException::class);
    });

    test('has correct message', function (): void {
        $exception = InvalidTotpCodeException::invalidCode();

        expect($exception->getMessage())->toBe('The provided TOTP code is invalid.');
    });

    test('extends SentinelException', function (): void {
        $exception = InvalidTotpCodeException::invalidCode();

        expect($exception)->toBeInstanceOf(SentinelException::class);
    });
});

describe('InvalidWebAuthnAssertionException', function (): void {
    test('can be instantiated', function (): void {
        $exception = InvalidWebAuthnAssertionException::invalidAssertion();

        expect($exception)->toBeInstanceOf(InvalidWebAuthnAssertionException::class);
    });

    test('has correct message', function (): void {
        $exception = InvalidWebAuthnAssertionException::invalidAssertion();

        expect($exception->getMessage())->toBe('The provided WebAuthn assertion is invalid.');
    });

    test('extends SentinelException', function (): void {
        $exception = InvalidWebAuthnAssertionException::invalidAssertion();

        expect($exception)->toBeInstanceOf(SentinelException::class);
    });
});

describe('MfaNotEnabledException', function (): void {
    test('can be instantiated', function (): void {
        $exception = MultiFactorNotEnabledException::forUser();

        expect($exception)->toBeInstanceOf(MultiFactorNotEnabledException::class);
    });

    test('has correct message', function (): void {
        $exception = MultiFactorNotEnabledException::forUser();

        expect($exception->getMessage())->toBe('Multi-factor authentication is not enabled for this user.');
    });

    test('extends SentinelException', function (): void {
        $exception = MultiFactorNotEnabledException::forUser();

        expect($exception)->toBeInstanceOf(SentinelException::class);
    });
});

describe('TotpSetupNotInitializedException', function (): void {
    test('can be instantiated', function (): void {
        $exception = TotpSetupNotInitializedException::create();

        expect($exception)->toBeInstanceOf(TotpSetupNotInitializedException::class);
    });

    test('has correct message', function (): void {
        $exception = TotpSetupNotInitializedException::create();

        expect($exception->getMessage())->toBe('TOTP setup has not been initialized. Call beginSetup() first.');
    });

    test('implements SentinelException', function (): void {
        $exception = TotpSetupNotInitializedException::create();

        expect($exception)->toBeInstanceOf(SentinelException::class);
    });
});

describe('WebAuthnSetupNotInitializedException', function (): void {
    test('can be instantiated', function (): void {
        $exception = WebAuthnSetupNotInitializedException::create();

        expect($exception)->toBeInstanceOf(WebAuthnSetupNotInitializedException::class);
    });

    test('has correct message', function (): void {
        $exception = WebAuthnSetupNotInitializedException::create();

        expect($exception->getMessage())->toBe('WebAuthn setup has not been initialized. Call beginRegistration() first.');
    });

    test('implements SentinelException', function (): void {
        $exception = WebAuthnSetupNotInitializedException::create();

        expect($exception)->toBeInstanceOf(SentinelException::class);
    });
});

describe('SentinelException', function (): void {
    test('is implemented by concrete exceptions', function (): void {
        $exception = InvalidTotpCodeException::invalidCode();

        expect($exception)->toBeInstanceOf(SentinelException::class);
    });

    test('extends Throwable', function (): void {
        $reflection = new ReflectionClass(SentinelException::class);

        expect($reflection->isInterface())->toBeTrue()
            ->and($reflection->implementsInterface(Throwable::class))->toBeTrue();
    });
});
