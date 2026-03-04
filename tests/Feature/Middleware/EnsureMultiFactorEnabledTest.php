<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Http\Middleware\EnsureMultiFactorEnabled;
use Illuminate\Support\Facades\Route;

beforeEach(function (): void {
    $this->user = createUser();

    // Define test routes with the middleware
    Route::middleware(['web', EnsureMultiFactorEnabled::class])->get('/protected', fn () => response()->json(['message' => 'success']))->name('protected');

    Route::get('/sentinel/setup', fn () => response()->json(['message' => 'setup page']))->name('sentinel.setup');
});

test('authenticated user with MFA enabled passes through', function (): void {
    // Arrange: Create user with TOTP credential (MFA enabled)
    createTotpCredential($this->user);

    // Act: Make authenticated request to protected route
    $response = $this->actingAs($this->user)->get('/protected');

    // Assert: Request passes through middleware successfully
    $response->assertStatus(200)
        ->assertJson(['message' => 'success']);
});

test('authenticated user without MFA redirects to setup with error message', function (): void {
    // Arrange: User without any MFA credentials
    // (no TOTP, WebAuthn, or recovery codes)

    // Act: Make authenticated request to protected route
    $response = $this->actingAs($this->user)->get('/protected');

    // Assert: Redirects to setup page with error message
    $response->assertRedirect(route('sentinel.setup'))
        ->assertSessionHas('error', 'You must enable multi-factor authentication to access this resource.');
});

test('unauthenticated user passes through', function (): void {
    // Arrange: No authenticated user (guest)

    // Act: Make unauthenticated request to protected route
    $response = $this->get('/protected');

    // Assert: Request passes through middleware (Laravel auth handles actual protection)
    $response->assertStatus(200)
        ->assertJson(['message' => 'success']);
});

test('authenticated user with WebAuthn credential passes through', function (): void {
    // Arrange: Create user with WebAuthn credential (another form of MFA)
    createWebAuthnCredential($this->user);

    // Act: Make authenticated request to protected route
    $response = $this->actingAs($this->user)->get('/protected');

    // Assert: Request passes through middleware successfully
    $response->assertStatus(200)
        ->assertJson(['message' => 'success']);
});

test('authenticated user with multiple MFA methods enabled passes through', function (): void {
    // Arrange: Create user with both TOTP and WebAuthn credentials
    createTotpCredential($this->user);
    createWebAuthnCredential($this->user);

    // Act: Make authenticated request to protected route
    $response = $this->actingAs($this->user)->get('/protected');

    // Assert: Request passes through middleware successfully
    $response->assertStatus(200)
        ->assertJson(['message' => 'success']);
});

test('middleware can be used on multiple routes', function (): void {
    // Arrange: Define another protected route
    Route::middleware(['web', EnsureMultiFactorEnabled::class])->get('/another-protected', fn () => response()->json(['message' => 'another success']));

    createTotpCredential($this->user);

    // Act: Access both protected routes
    $response1 = $this->actingAs($this->user)->get('/protected');
    $response2 = $this->actingAs($this->user)->get('/another-protected');

    // Assert: Both requests succeed
    $response1->assertStatus(200);
    $response2->assertStatus(200)->assertJson(['message' => 'another success']);
});

test('middleware blocks user without MFA on POST requests', function (): void {
    // Arrange: User without MFA credentials, define POST route
    Route::middleware(['web', EnsureMultiFactorEnabled::class])->post('/protected-action', fn () => response()->json(['message' => 'action completed']));

    // Act: Make authenticated POST request
    $response = $this->actingAs($this->user)->post('/protected-action');

    // Assert: Redirects to setup page
    $response->assertRedirect(route('sentinel.setup'))
        ->assertSessionHas('error');
});

test('middleware allows user with MFA on POST requests', function (): void {
    // Arrange: User with MFA, define POST route
    createTotpCredential($this->user);

    Route::middleware(['web', EnsureMultiFactorEnabled::class])->post('/protected-action', fn () => response()->json(['message' => 'action completed']));

    // Act: Make authenticated POST request
    $response = $this->actingAs($this->user)->post('/protected-action');

    // Assert: Request succeeds
    $response->assertStatus(200)
        ->assertJson(['message' => 'action completed']);
});

test('error message is accessible in session after redirect', function (): void {
    // Arrange: User without MFA

    // Act: Make authenticated request
    $response = $this->actingAs($this->user)->get('/protected');

    // Assert: Error message is in session
    $response->assertRedirect(route('sentinel.setup'));

    expect(session('error'))
        ->toBe('You must enable multi-factor authentication to access this resource.');
});
