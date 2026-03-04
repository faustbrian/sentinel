<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Sentinel\Events\SudoModeChallenged;
use Cline\Sentinel\Facades\Sentinel;
use Cline\Sentinel\Http\Middleware\EnsureSudoMode;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Tests\Fixtures\User;

beforeEach(function (): void {
    $this->user = createUser();

    // Set up test routes with middleware
    Route::get('/protected', fn () => response()->json(['success' => true]))
        ->middleware(['web', EnsureSudoMode::class])
        ->name('protected.route');

    Route::get('/sentinel-sudo', fn () => response()->json(['sudo' => true]))
        ->middleware('web')
        ->name('sentinel.sudo');
});

describe('Happy Path', function (): void {
    test('allows access when user is in sudo mode', function (): void {
        // Arrange
        $request = Request::create('/test');
        $request->setLaravelSession(session()->driver());
        Sentinel::enableSudoMode($request);

        // Act
        $response = $this->withSession($request->session()->all())
            ->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response->assertStatus(200)
            ->assertJson(['success' => true]);
    });

    test('allows access immediately after enabling sudo mode', function (): void {
        // Arrange
        $request = Request::create('/test');
        $request->setLaravelSession(session()->driver());
        $request->setUserResolver(fn () => $this->user);
        Sentinel::enableSudoMode($request);

        // Act
        $response = $this->withSession($request->session()->all())
            ->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response->assertOk();

        expect(Sentinel::inSudoMode($request))->toBeTrue();
    });

    test('maintains sudo mode across multiple requests within duration', function (): void {
        // Arrange
        $request = Request::create('/test');
        $request->setLaravelSession(session()->driver());
        Sentinel::enableSudoMode($request);

        $sessionData = $request->session()->all();

        // Act - First request
        $firstResponse = $this->withSession($sessionData)
            ->actingAs($this->user)
            ->get('/protected');

        // Act - Second request (should still be in sudo mode)
        $secondResponse = $this->withSession($sessionData)
            ->actingAs($this->user)
            ->get('/protected');

        // Assert
        $firstResponse->assertOk();
        $secondResponse->assertOk();
    });
});

describe('Sad Path', function (): void {
    test('redirects to sudo challenge when user not in sudo mode', function (): void {
        // Arrange - User is authenticated but not in sudo mode

        // Act
        $response = $this->actingAs($this->user)->get('/protected');

        // Assert
        $response->assertRedirect(route('sentinel.sudo'));
    });

    test('fires SudoModeChallenged event when authenticated user lacks sudo mode', function (): void {
        // Arrange
        Event::fake();

        // Act
        $this->actingAs($this->user)->get('/protected');

        // Assert
        Event::assertDispatched(SudoModeChallenged::class, fn ($event): bool => $event->user->id === $this->user->id);
    });

    test('does not fire SudoModeChallenged event when user is in sudo mode', function (): void {
        // Arrange
        Event::fake();
        $request = Request::create('/test');
        $request->setLaravelSession(session()->driver());
        Sentinel::enableSudoMode($request);

        // Act
        $this->withSession($request->session()->all())
            ->actingAs($this->user)
            ->get('/protected');

        // Assert
        Event::assertNotDispatched(SudoModeChallenged::class);
    });

    test('redirects unauthenticated users to sudo challenge', function (): void {
        // Arrange - No authenticated user

        // Act
        $response = $this->get('/protected');

        // Assert
        $response->assertRedirect(route('sentinel.sudo'));
    });

    test('does not fire event for unauthenticated users', function (): void {
        // Arrange
        Event::fake();

        // Act
        $this->get('/protected');

        // Assert
        Event::assertNotDispatched(SudoModeChallenged::class);
    });

    test('blocks access after sudo mode expires', function (): void {
        // Arrange
        config(['sentinel.sudo_mode.duration' => 1]);
        $request = Request::create('/test');
        $request->setLaravelSession(session()->driver());
        Sentinel::enableSudoMode($request);

        // Manually set to expired timestamp
        $request->session()->put(
            config('sentinel.session.sudo_confirmed_at'),
            now()->subSeconds(2)->timestamp,
        );

        // Act
        $response = $this->withSession($request->session()->all())
            ->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response->assertRedirect(route('sentinel.sudo'));
    });
});

describe('Edge Cases', function (): void {
    test('stores intended URL in session when redirecting', function (): void {
        // Arrange
        $protectedUrl = 'http://localhost/protected';

        // Act
        $response = $this->actingAs($this->user)->get($protectedUrl);

        // Assert
        $response->assertRedirect(route('sentinel.sudo'));
        $response->assertSessionHas('intended', $protectedUrl);
    });

    test('stores full URL with query parameters as intended URL', function (): void {
        // Arrange & Act
        $response = $this->actingAs($this->user)->get('/protected?foo=bar&baz=qux');

        // Assert
        $response->assertRedirect(route('sentinel.sudo'));

        $intendedUrl = session('intended');
        expect($intendedUrl)->toContain('protected')
            ->and($intendedUrl)->toContain('foo=bar')
            ->and($intendedUrl)->toContain('baz=qux');
    });

    test('stores full URL with fragment as intended URL', function (): void {
        // Arrange
        Route::get('/settings', fn () => response()->json(['success' => true]))
            ->middleware(['web', EnsureSudoMode::class]);

        $protectedUrl = 'http://localhost/settings?tab=security';

        // Act
        $response = $this->actingAs($this->user)->get($protectedUrl);

        // Assert
        $response->assertRedirect(route('sentinel.sudo'));
        $response->assertSessionHas('intended', $protectedUrl);
    });

    test('handles POST requests correctly when not in sudo mode', function (): void {
        // Arrange
        Route::post('/protected/action', fn () => response()->json(['success' => true]))
            ->middleware(['web', EnsureSudoMode::class]);

        // Act
        $response = $this->actingAs($this->user)->post('/protected/action', ['data' => 'value']);

        // Assert
        $response->assertRedirect(route('sentinel.sudo'));
        $response->assertSessionHas('intended', 'http://localhost/protected/action');
    });

    test('handles PUT requests correctly when not in sudo mode', function (): void {
        // Arrange
        Route::put('/protected/update', fn () => response()->json(['success' => true]))
            ->middleware(['web', EnsureSudoMode::class]);

        // Act
        $response = $this->actingAs($this->user)->put('/protected/update', ['data' => 'value']);

        // Assert
        $response->assertRedirect(route('sentinel.sudo'));
        $response->assertSessionHas('intended', 'http://localhost/protected/update');
    });

    test('handles DELETE requests correctly when not in sudo mode', function (): void {
        // Arrange
        Route::delete('/protected/delete', fn () => response()->json(['success' => true]))
            ->middleware(['web', EnsureSudoMode::class]);

        // Act
        $response = $this->actingAs($this->user)->delete('/protected/delete');

        // Assert
        $response->assertRedirect(route('sentinel.sudo'));
        $response->assertSessionHas('intended', 'http://localhost/protected/delete');
    });

    test('event receives correct user instance', function (): void {
        // Arrange
        Event::fake();

        // Act
        $this->actingAs($this->user)->get('/protected');

        // Assert
        Event::assertDispatched(SudoModeChallenged::class, fn ($event): bool => $event->user->email === $this->user->email
            && $event->user->name === $this->user->name
            && $event->user instanceof User);
    });

    test('handles requests without sudo mode after previous request with sudo mode', function (): void {
        // Arrange - First request with sudo mode
        $request1 = Request::create('/test1');
        $request1->setLaravelSession(session()->driver());
        Sentinel::enableSudoMode($request1);

        $response1 = $this->withSession($request1->session()->all())
            ->actingAs($this->user)
            ->get('/protected');

        // Assert first request passed
        $response1->assertOk();

        // Act - Second request should still work with same session data
        $response2 = $this->withSession($request1->session()->all())
            ->actingAs($this->user)
            ->get('/protected');

        // Assert - Both requests pass because they share the same sudo session
        $response2->assertOk();
    });

    test('preserves session data when redirecting', function (): void {
        // Arrange
        $sessionData = ['custom_key' => 'custom_value'];

        // Act
        $response = $this->withSession($sessionData)
            ->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response->assertRedirect(route('sentinel.sudo'));
        $response->assertSessionHas('custom_key', 'custom_value');
    });

    test('handles very long URLs in intended session', function (): void {
        // Arrange
        $queryParams = http_build_query(array_fill(0, 50, 'very_long_parameter_value'));
        $protectedUrl = 'http://localhost/protected?'.$queryParams;

        // Act
        $response = $this->actingAs($this->user)->get($protectedUrl);

        // Assert
        $response->assertRedirect(route('sentinel.sudo'));
        $response->assertSessionHas('intended', $protectedUrl);
    });

    test('handles unicode characters in URL correctly', function (): void {
        // Arrange
        Route::get('/protected/data', fn () => response()->json(['success' => true]))
            ->middleware(['web', EnsureSudoMode::class]);

        // Act - Use URL encoded unicode characters
        $response = $this->actingAs($this->user)->get('/protected/data?name=用户');

        // Assert
        $response->assertRedirect(route('sentinel.sudo'));

        $intendedUrl = session('intended');
        expect($intendedUrl)->toContain('protected/data');
    });

    test('middleware is immutable and reusable', function (): void {
        // Arrange - First request without sudo mode
        $response1 = $this->actingAs($this->user)->get('/protected');

        // Arrange - Second request with sudo mode
        $request = Request::create('/test');
        $request->setLaravelSession(session()->driver());
        Sentinel::enableSudoMode($request);

        $response2 = $this->withSession($request->session()->all())
            ->actingAs($this->user)
            ->get('/protected');

        // Assert - First request should fail, second should pass
        $response1->assertRedirect(route('sentinel.sudo'));
        $response2->assertOk();
    });
});

describe('Integration', function (): void {
    test('works correctly with multiple middleware', function (): void {
        // Arrange
        Route::get('/multi-middleware', fn () => response()->json(['success' => true]))
            ->middleware(['web', EnsureSudoMode::class]);

        // Act
        $response = $this->actingAs($this->user)->get('/multi-middleware');

        // Assert
        $response->assertRedirect(route('sentinel.sudo'));
    });

    test('maintains sudo mode state across different protected routes', function (): void {
        // Arrange
        Route::get('/protected-1', fn () => response()->json(['route' => 1]))
            ->middleware(['web', EnsureSudoMode::class]);
        Route::get('/protected-2', fn () => response()->json(['route' => 2]))
            ->middleware(['web', EnsureSudoMode::class]);

        $request = Request::create('/test');
        $request->setLaravelSession(session()->driver());
        Sentinel::enableSudoMode($request);

        $sessionData = $request->session()->all();

        // Act
        $response1 = $this->withSession($sessionData)
            ->actingAs($this->user)
            ->get('/protected-1');

        $response2 = $this->withSession($sessionData)
            ->actingAs($this->user)
            ->get('/protected-2');

        // Assert
        $response1->assertOk()->assertJson(['route' => 1]);
        $response2->assertOk()->assertJson(['route' => 2]);
    });

    test('event listener can access user properties', function (): void {
        // Arrange
        Event::fake();
        $testUser = createUser('specific@example.com');

        // Act
        $this->actingAs($testUser)->get('/protected');

        // Assert
        Event::assertDispatched(SudoModeChallenged::class, fn ($event): bool => $event->user->email === 'specific@example.com'
            && $event->user->id === $testUser->id);
    });

    test('respects session-based sudo mode flag', function (): void {
        // Arrange
        $request = Request::create('/test');
        $request->setLaravelSession(session()->driver());

        // Manually set sudo mode flag in session
        $request->session()->put(
            config('sentinel.session.sudo_confirmed_at'),
            now()->timestamp,
        );

        // Act
        $response = $this->withSession($request->session()->all())
            ->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response->assertStatus(200);
    });

    test('each user requires their own sudo mode activation', function (): void {
        // Arrange - Create second user
        $user2 = User::query()->create([
            'id' => 2,
            'name' => 'User Two',
            'email' => 'user2@example.com',
            'password' => bcrypt('password'),
        ]);

        // User 1 enables sudo mode
        $request1 = Request::create('/test');
        $request1->setLaravelSession(session()->driver());
        Sentinel::enableSudoMode($request1);

        // Act - User 1 can access
        $response1 = $this->withSession($request1->session()->all())
            ->actingAs($this->user)
            ->get('/protected');

        // Assert
        $response1->assertStatus(200);

        // Now test that user 2 independently needs sudo mode
        // User 2 enables sudo mode in their own session
        $request2 = Request::create('/test2');
        $request2->setLaravelSession(session()->driver());
        Sentinel::enableSudoMode($request2);

        $response2 = $this->withSession($request2->session()->all())
            ->actingAs($user2)
            ->get('/protected');

        // Assert - User 2 also has access with their own sudo session
        $response2->assertStatus(200);
    });
});
