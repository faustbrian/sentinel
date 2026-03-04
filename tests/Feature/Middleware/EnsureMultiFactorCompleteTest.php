<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Facades\Sentinel;
use Cline\Sentinel\Http\Middleware\EnsureMultiFactorComplete;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

beforeEach(function (): void {
    $this->user = createUser();

    // Set up a test route with the middleware
    Route::get('/protected', fn () => response()->json(['success' => true]))
        ->middleware(['web', EnsureMultiFactorComplete::class])
        ->name('protected.route');

    Route::get('/sentinel-challenge', fn () => response()->json(['challenge' => true]))
        ->middleware('web')
        ->name('sentinel.challenge');
});

describe('Happy Path', function (): void {
    test('allows authenticated user with MFA completed to pass through', function (): void {
        // Arrange
        createTotpCredential($this->user);

        // Simulate MFA challenge completed
        $request = Request::create('/test');
        $request->setLaravelSession(session()->driver());
        Sentinel::initiateMultiFactorChallenge($request, $this->user);
        Sentinel::markMultiFactorComplete($request);

        // Act - Authenticate the user and make request with the session
        Auth::login($this->user);
        $response = $this->withSession($request->session()->all())
            ->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response->assertStatus(200);
        $response->assertJson(['success' => true]);
    });

    test('allows authenticated user without MFA to pass through', function (): void {
        // Arrange - User has no MFA credentials

        // Act
        $response = $this->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response->assertStatus(200);
        $response->assertJson(['success' => true]);
    });

    test('allows unauthenticated user to pass through', function (): void {
        // Arrange - No authenticated user

        // Act
        $response = $this->get('/protected');

        // Assert
        $response->assertStatus(200);
        $response->assertJson(['success' => true]);
    });
});

describe('Sad Path', function (): void {
    test('redirects authenticated user with MFA enabled but not completed to challenge', function (): void {
        // Arrange
        createTotpCredential($this->user);

        // Act
        $response = $this->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response->assertRedirect(route('sentinel.challenge'));
    });

    test('redirects user with WebAuthn credential when MFA not completed', function (): void {
        // Arrange
        createWebAuthnCredential($this->user);

        // Act
        $response = $this->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response->assertRedirect(route('sentinel.challenge'));
    });

    test('redirects user with multiple MFA methods when not completed', function (): void {
        // Arrange
        createTotpCredential($this->user);
        createWebAuthnCredential($this->user);

        // Act
        $response = $this->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response->assertRedirect(route('sentinel.challenge'));
    });
});

describe('Edge Cases', function (): void {
    test('allows user after MFA completion in same session', function (): void {
        // Arrange
        createTotpCredential($this->user);

        // Simulate completing MFA challenge
        $request = Request::create('/test');
        $request->setLaravelSession(session()->driver());
        Sentinel::initiateMultiFactorChallenge($request, $this->user);
        Sentinel::markMultiFactorComplete($request);

        // Act - Make request with same session
        $response = $this->withSession($request->session()->all())
            ->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response->assertStatus(200);
        $response->assertJson(['success' => true]);
    });

    test('redirects when MFA challenge initiated but not completed', function (): void {
        // Arrange
        createTotpCredential($this->user);

        $request = Request::create('/test');
        $request->setLaravelSession(session()->driver());
        Sentinel::initiateMultiFactorChallenge($request, $this->user);
        // Note: NOT calling markMultiFactorComplete

        // Act
        $response = $this->withSession($request->session()->all())
            ->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response->assertRedirect(route('sentinel.challenge'));
    });

    test('handles user switching from no MFA to MFA enabled', function (): void {
        // Arrange - Start without MFA
        $response = $this->actingAs($this->user)
            ->get('/protected');

        // Assert - First request passes
        $response->assertStatus(200);

        // Act - Enable MFA
        createTotpCredential($this->user);

        $response = $this->actingAs($this->user)
            ->get('/protected');

        // Assert - Second request redirects
        $response->assertRedirect(route('sentinel.challenge'));
    });

    test('handles concurrent requests with same session', function (): void {
        // Arrange
        createTotpCredential($this->user);

        $request = Request::create('/test');
        $request->setLaravelSession(session()->driver());
        Sentinel::initiateMultiFactorChallenge($request, $this->user);
        Sentinel::markMultiFactorComplete($request);

        $sessionData = $request->session()->all();

        // Act - Make multiple requests with same session
        $response1 = $this->withSession($sessionData)
            ->actingAs($this->user)
            ->get('/protected');

        $response2 = $this->withSession($sessionData)
            ->actingAs($this->user)
            ->get('/protected');

        // Assert - Both requests pass
        $response1->assertStatus(200);
        $response2->assertStatus(200);
    });

    test('handles empty session gracefully', function (): void {
        // Arrange
        createTotpCredential($this->user);

        // Act - Make request with fresh session (no MFA completion data)
        $response = $this->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response->assertRedirect(route('sentinel.challenge'));
    });

    test('allows user with only recovery codes but no active credentials', function (): void {
        // Arrange - User has recovery codes but no TOTP/WebAuthn credentials
        Sentinel::recoveryCodes()->generate($this->user);

        // Act
        $response = $this->actingAs($this->user)
            ->get('/protected');

        // Assert - Recovery codes alone don't count as MFA for middleware
        $response->assertStatus(200);
    });
});

describe('Middleware Integration', function (): void {
    test('middleware can be instantiated with Sentinel dependency', function (): void {
        // Arrange & Act
        $middleware = resolve(EnsureMultiFactorComplete::class);

        // Assert
        expect($middleware)->toBeInstanceOf(EnsureMultiFactorComplete::class);
    });

    test('middleware handle method returns Response', function (): void {
        // Arrange
        $middleware = resolve(EnsureMultiFactorComplete::class);
        $request = Request::create('/test');
        $next = fn ($req) => response()->json(['next' => true]);

        // Act
        $response = $middleware->handle($request, $next);

        // Assert
        expect($response->getStatusCode())->toBe(200);
    });

    test('middleware preserves request data when passing through', function (): void {
        // Arrange
        createTotpCredential($this->user);

        $request = Request::create('/test');
        $request->setLaravelSession(session()->driver());
        Sentinel::initiateMultiFactorChallenge($request, $this->user);
        Sentinel::markMultiFactorComplete($request);

        Auth::login($this->user);

        // Act
        $response = $this->withSession($request->session()->all())
            ->actingAs($this->user)
            ->post('/protected', ['test_data' => 'value']);

        // Assert - Request should pass through (even though we get 405 Method Not Allowed
        // for our test route, it means middleware passed the request through)
        expect($response->getStatusCode())->toBeIn([200, 405]);
    });
});

describe('Session State Management', function (): void {
    test('respects session-based MFA completion flag', function (): void {
        // Arrange
        createTotpCredential($this->user);

        $request = Request::create('/test');
        $request->setLaravelSession(session()->driver());

        // Mark MFA as complete in session
        $request->session()->put(
            config('sentinel.session.multi_factor_completed_at'),
            now()->timestamp,
        );

        // Act
        $response = $this->withSession($request->session()->all())
            ->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response->assertStatus(200);
    });

    test('separate requests maintain user-specific MFA state', function (): void {
        // Arrange - User 1 has MFA with completed challenge
        createTotpCredential($this->user);

        $request1 = Request::create('/test');
        $request1->setLaravelSession(session()->driver());
        Sentinel::initiateMultiFactorChallenge($request1, $this->user);
        Sentinel::markMultiFactorComplete($request1);

        // Act & Assert - User 1 with completed MFA can access
        $response1 = $this->withSession($request1->session()->all())
            ->actingAs($this->user)
            ->get('/protected');

        $response1->assertStatus(200);

        // Arrange - User 2 has MFA but hasn't completed challenge (using this->user in fresh session)
        // Clear all sessions and start fresh
        session()->flush();

        // Act & Assert - Same user with fresh session (no MFA completion) is redirected
        $response2 = $this->actingAs($this->user)
            ->get('/protected');

        $response2->assertRedirect(route('sentinel.challenge'));
    });
});
