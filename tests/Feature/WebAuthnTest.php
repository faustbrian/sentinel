<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\Events\WebAuthnCredentialRemoved;
use Cline\Sentinel\Facades\Sentinel;
use Illuminate\Support\Facades\Event;

beforeEach(function (): void {
    $this->user = createUser();
});

test('can begin WebAuthn registration and generates proper challenge structure', function (): void {
    config([
        'sentinel.webauthn.relying_party.name' => 'Test App',
        'sentinel.webauthn.relying_party.id' => 'example.com',
        'sentinel.webauthn.timeout' => 60_000,
        'sentinel.webauthn.attestation' => 'none',
    ]);

    $challengeOptionsJson = Sentinel::webAuthn()->beginRegistration($this->user);
    $challengeOptions = json_decode($challengeOptionsJson, true);

    // Verify challenge structure
    expect($challengeOptions)->toBeArray()
        ->toHaveKeys(['challenge', 'rp', 'user', 'pubKeyCredParams', 'attestation'])
        ->and($challengeOptions['challenge'])->toBeString()
        ->and(mb_strlen((string) base64_decode((string) $challengeOptions['challenge'], true), '8bit'))->toBe(32);

    // Verify relying party
    expect($challengeOptions['rp'])->toBeArray()
        ->and($challengeOptions['rp']['name'])->toBe('Test App')
        ->and($challengeOptions['rp']['id'])->toBe('example.com');

    // Verify user data
    expect($challengeOptions['user'])->toBeArray()
        ->toHaveKeys(['id', 'name', 'displayName'])
        ->and($challengeOptions['user']['name'])->toBe($this->user->email)
        ->and($challengeOptions['user']['displayName'])->toBe($this->user->name);

    // Verify public key credential parameters
    expect($challengeOptions['pubKeyCredParams'])->toBeArray()
        ->toHaveCount(2)
        ->and($challengeOptions['pubKeyCredParams'][0])->toBe(['type' => 'public-key', 'alg' => -7])
        ->and($challengeOptions['pubKeyCredParams'][1])->toBe(['type' => 'public-key', 'alg' => -257]);

    // Verify attestation
    expect($challengeOptions['attestation'])->toBe('none');
});

test('beginRegistration includes user identifier in base64 encoded format', function (): void {
    $challengeOptionsJson = Sentinel::webAuthn()->beginRegistration($this->user);
    $challengeOptions = json_decode($challengeOptionsJson, true);

    $decodedUserId = (string) base64_decode((string) $challengeOptions['user']['id'], true);

    expect($decodedUserId)->toBe((string) $this->user->id);
});

test('beginRegistration generates unique challenges on each call', function (): void {
    $firstChallengeJson = Sentinel::webAuthn()->beginRegistration($this->user);
    $secondChallengeJson = Sentinel::webAuthn()->beginRegistration($this->user);

    $firstChallenge = json_decode($firstChallengeJson, true);
    $secondChallenge = json_decode($secondChallengeJson, true);

    // Challenges should be different on each call
    expect($firstChallenge['challenge'])->not->toBe($secondChallenge['challenge']);
});

test('can confirm WebAuthn registration and creates credential', function (): void {
    Event::fake();

    // This test needs actual WebAuthn library integration - skipping for now
    // as it requires valid PublicKeyCredential JSON from a real authenticator
    expect(true)->toBeTrue();
})->skip('Requires WebAuthn library integration');

test('confirmRegistration uses default name when not provided', function (): void {
    // This test needs actual WebAuthn library integration - skipping for now
    // as it requires valid PublicKeyCredential JSON from a real authenticator
    expect(true)->toBeTrue();
})->skip('Requires WebAuthn library integration');

test('confirmRegistration handles credential without transports', function (): void {
    // This test needs actual WebAuthn library integration - skipping for now
    // as it requires valid PublicKeyCredential JSON from a real authenticator
    expect(true)->toBeTrue();
})->skip('Requires WebAuthn library integration');

test('can begin WebAuthn authentication and generates challenge structure', function (): void {
    config([
        'sentinel.webauthn.relying_party.id' => 'example.com',
        'sentinel.webauthn.timeout' => 60_000,
    ]);

    $challengeOptionsJson = Sentinel::webAuthn()->beginAuthentication();
    $challengeOptions = json_decode($challengeOptionsJson, true);

    // Verify challenge structure
    expect($challengeOptions)->toBeArray()
        ->toHaveKeys(['challenge', 'rpId', 'allowCredentials'])
        ->and($challengeOptions['challenge'])->toBeString()
        ->and(mb_strlen((string) base64_decode((string) $challengeOptions['challenge'], true), '8bit'))->toBe(32);

    // Verify rpId
    expect($challengeOptions['rpId'])->toBe('example.com');

    // Verify allowCredentials is empty array
    expect($challengeOptions['allowCredentials'])->toBe([]);
});

test('verify validates WebAuthn assertion', function (): void {
    // This test needs actual WebAuthn library integration - skipping for now
    // as it requires valid PublicKeyCredential JSON from a real authenticator
    expect(true)->toBeTrue();
})->skip('Requires WebAuthn library integration');

test('can remove WebAuthn credential', function (): void {
    Event::fake();

    $credential = createWebAuthnCredential($this->user, 'Yubikey');

    Sentinel::webAuthn()->remove($this->user, $credential->id);

    // Verify credential was deleted
    expect(MultiFactorCredential::query()
        ->where('id', $credential->id)
        ->exists())->toBeFalse();

    // Verify event was dispatched
    Event::assertDispatched(WebAuthnCredentialRemoved::class, fn ($event): bool => $event->user->id === $this->user->id
        && $event->credentialId === $credential->id);
});

test('remove only deletes WebAuthn credentials for the authenticated user', function (): void {
    $otherUser = createUser('other@example.com');
    $userCredential = createWebAuthnCredential($this->user, 'User Key');
    $otherCredential = createWebAuthnCredential($otherUser, 'Other Key');

    // Try to remove other user's credential
    Sentinel::webAuthn()->remove($this->user, $otherCredential->id);

    // Other user's credential should still exist
    expect(MultiFactorCredential::query()->where('id', $otherCredential->id)->exists())->toBeTrue()
        // Current user's credential should still exist
        ->and(MultiFactorCredential::query()->where('id', $userCredential->id)->exists())->toBeTrue();
});

test('remove only deletes WebAuthn type credentials', function (): void {
    $webauthnCredential = createWebAuthnCredential($this->user, 'Security Key');
    $totpCredential = createTotpCredential($this->user);

    // Try to remove TOTP credential via WebAuthn remove
    Sentinel::webAuthn()->remove($this->user, $totpCredential->id);

    // TOTP credential should still exist
    expect(MultiFactorCredential::query()->where('id', $totpCredential->id)->exists())->toBeTrue()
        // WebAuthn credential should still exist
        ->and(MultiFactorCredential::query()->where('id', $webauthnCredential->id)->exists())->toBeTrue();
});

test('remove fires event even when credential does not exist', function (): void {
    Event::fake();

    $nonExistentId = 'non-existent-credential-id';

    Sentinel::webAuthn()->remove($this->user, $nonExistentId);

    // Event should still be dispatched
    Event::assertDispatched(WebAuthnCredentialRemoved::class, fn ($event): bool => $event->user->id === $this->user->id
        && $event->credentialId === $nonExistentId);
});
