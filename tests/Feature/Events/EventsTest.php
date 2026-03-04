<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Events\SudoModeChallenged;
use Cline\Sentinel\Events\WebAuthnCredentialRegistered;

beforeEach(function (): void {
    $this->user = createUser();
});

describe('SudoModeChallenged', function (): void {
    test('can be instantiated with user', function (): void {
        $event = new SudoModeChallenged(user: $this->user);

        expect($event)->toBeInstanceOf(SudoModeChallenged::class);
    });

    test('user property is accessible', function (): void {
        $event = new SudoModeChallenged(user: $this->user);

        expect($event->user)->toBe($this->user)
            ->and($event->user->email)->toBe('test@example.com')
            ->and($event->user->name)->toBe('Test User');
    });

    test('is immutable', function (): void {
        $event = new SudoModeChallenged(user: $this->user);

        expect($event)->toBeInstanceOf(SudoModeChallenged::class)
            ->and(
                new ReflectionClass($event)->isReadOnly(),
            )->toBeTrue();
    });

    test('can be dispatched', function (): void {
        $event = new SudoModeChallenged(user: $this->user);

        expect(method_exists($event, 'dispatch'))->toBeTrue();
    });
});

describe('WebAuthnCredentialRegistered', function (): void {
    test('can be instantiated with required parameters', function (): void {
        $event = new WebAuthnCredentialRegistered(
            user: $this->user,
            credentialId: 'credential-123',
            name: 'YubiKey 5',
        );

        expect($event)->toBeInstanceOf(WebAuthnCredentialRegistered::class);
    });

    test('user property is accessible', function (): void {
        $event = new WebAuthnCredentialRegistered(
            user: $this->user,
            credentialId: 'credential-123',
            name: 'YubiKey 5',
        );

        expect($event->user)->toBe($this->user)
            ->and($event->user->email)->toBe('test@example.com')
            ->and($event->user->name)->toBe('Test User');
    });

    test('credentialId property is accessible', function (): void {
        $event = new WebAuthnCredentialRegistered(
            user: $this->user,
            credentialId: 'credential-123',
            name: 'YubiKey 5',
        );

        expect($event->credentialId)->toBe('credential-123');
    });

    test('name property is accessible', function (): void {
        $event = new WebAuthnCredentialRegistered(
            user: $this->user,
            credentialId: 'credential-123',
            name: 'YubiKey 5',
        );

        expect($event->name)->toBe('YubiKey 5');
    });

    test('all properties are accessible together', function (): void {
        $credentialId = 'cred-456-xyz';
        $credentialName = 'Security Key';

        $event = new WebAuthnCredentialRegistered(
            user: $this->user,
            credentialId: $credentialId,
            name: $credentialName,
        );

        expect($event->user)->toBe($this->user)
            ->and($event->credentialId)->toBe($credentialId)
            ->and($event->name)->toBe($credentialName);
    });

    test('is immutable', function (): void {
        $event = new WebAuthnCredentialRegistered(
            user: $this->user,
            credentialId: 'credential-123',
            name: 'YubiKey 5',
        );

        expect($event)->toBeInstanceOf(WebAuthnCredentialRegistered::class)
            ->and(
                new ReflectionClass($event)->isReadOnly(),
            )->toBeTrue();
    });

    test('can be dispatched', function (): void {
        $event = new WebAuthnCredentialRegistered(
            user: $this->user,
            credentialId: 'credential-123',
            name: 'YubiKey 5',
        );

        expect(method_exists($event, 'dispatch'))->toBeTrue();
    });

    test('handles empty credential name', function (): void {
        $event = new WebAuthnCredentialRegistered(
            user: $this->user,
            credentialId: 'credential-789',
            name: '',
        );

        expect($event->name)->toBe('');
    });

    test('handles special characters in credential name', function (): void {
        $specialName = "User's Key #1 (Main)";

        $event = new WebAuthnCredentialRegistered(
            user: $this->user,
            credentialId: 'credential-special',
            name: $specialName,
        );

        expect($event->name)->toBe($specialName);
    });

    test('handles unicode in credential name', function (): void {
        $unicodeName = '🔐 Security Key';

        $event = new WebAuthnCredentialRegistered(
            user: $this->user,
            credentialId: 'credential-unicode',
            name: $unicodeName,
        );

        expect($event->name)->toBe($unicodeName);
    });

    test('handles long credential id', function (): void {
        $longCredentialId = str_repeat('a', 500);

        $event = new WebAuthnCredentialRegistered(
            user: $this->user,
            credentialId: $longCredentialId,
            name: 'Test Key',
        );

        expect($event->credentialId)->toBe($longCredentialId)
            ->and(mb_strlen($event->credentialId))->toBe(500);
    });
});
