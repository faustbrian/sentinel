Sentinel provides three middleware classes to enforce multi-factor requirements and security policies across your application.

## Available Middleware

Sentinel registers three middleware aliases:

| Alias | Class | Purpose |
|-------|-------|---------|
| `multi-factor.complete` | `EnsureMfaComplete` | Ensures user completed multi-factor challenge |
| `multi-factor.required` | `EnsureMfaEnabled` | Requires user to have multi-factor enabled |
| `sudo` | `EnsureSudoMode` | Requires sudo mode for sensitive actions |

## multi-factor Complete Middleware

Ensures users who have multi-factor enabled must complete the challenge before accessing routes.

### Usage

```php
use Illuminate\Support\Facades\Route;

// Protect individual routes
Route::get('/dashboard', [DashboardController::class, 'index'])
    ->middleware(['auth', 'multi-factor.complete']);

// Protect route groups
Route::middleware(['auth', 'multi-factor.complete'])->group(function () {
    Route::get('/dashboard', ...);
    Route::get('/profile', ...);
    Route::get('/settings', ...);
});
```

### How It Works

1. User logs in successfully
2. If user has multi-factor enabled, they're redirected to multi-factor challenge
3. Middleware blocks access until multi-factor is completed
4. Once verified, user can access protected routes

### Configuration

Configure the challenge route in `config/sentinel.php`:

```php
'routes' => [
    'mfa_challenge' => 'mfa.challenge',
],
```

### Example Flow

```php
// Login controller
public function authenticate(Request $request)
{
    // ... validate credentials ...

    if (Sentinel::for($user)->hasMultiFactorAuth()) {
        Sentinel::initiateMfaChallenge($request, $user);
        return redirect()->route('mfa.challenge');
    }

    Auth::login($user);
    return redirect('/dashboard');
}

// Dashboard route (protected)
Route::get('/dashboard', function () {
    return view('dashboard');
})->middleware(['auth', 'multi-factor.complete']);

// multi-factor challenge page (NOT protected by multi-factor.complete)
Route::get('/mfa/challenge', [MfaController::class, 'show'])
    ->name('mfa.challenge')
    ->middleware('auth');

Route::post('/mfa/verify', [MfaController::class, 'verify'])
    ->name('mfa.verify')
    ->middleware('auth');
```

## multi-factor Required Middleware

Forces users to have multi-factor enabled to access specific routes. Redirects users without multi-factor to setup page.

### Usage

```php
// Require multi-factor for admin routes
Route::middleware(['auth', 'multi-factor.required'])->group(function () {
    Route::get('/admin', ...);
    Route::get('/admin/users', ...);
    Route::post('/admin/settings', ...);
});

// Combine with multi-factor.complete for full protection
Route::middleware(['auth', 'multi-factor.required', 'multi-factor.complete'])->group(function () {
    Route::get('/admin', ...);
});
```

### Configuration

Configure the setup route in `config/sentinel.php`:

```php
'routes' => [
    'mfa_setup' => 'mfa.setup',
],
```

### Example Flow

```php
// User without multi-factor tries to access /admin
// Middleware redirects to mfa.setup

// Setup route
Route::get('/mfa/setup', [MfaController::class, 'setup'])
    ->name('mfa.setup')
    ->middleware('auth');

Route::post('/mfa/enable', [MfaController::class, 'enable'])
    ->name('mfa.enable')
    ->middleware('auth');

// multi-factor setup controller
public function setup()
{
    $setup = Sentinel::totp()->beginSetup(auth()->user());

    return view('auth.mfa-setup', [
        'qrCode' => $setup->getQrCodeSvg(),
        'secret' => $setup->getSecret(),
    ]);
}

public function enable(Request $request)
{
    $confirmed = Sentinel::totp()->confirmSetup(
        $request->user(),
        $request->input('code')
    );

    if (!$confirmed) {
        return back()->withErrors(['code' => 'Invalid code.']);
    }

    $codes = Sentinel::recoveryCodes()->generate($request->user());

    return view('auth.recovery-codes', ['codes' => $codes]);
}
```

### Use Cases

**Admin Access:**
```php
Route::prefix('admin')->middleware(['auth', 'multi-factor.required'])->group(function () {
    Route::get('/', [AdminController::class, 'dashboard']);
    Route::resource('users', UserController::class);
});
```

**Financial Operations:**
```php
Route::middleware(['auth', 'multi-factor.required'])->group(function () {
    Route::get('/billing', ...);
    Route::post('/billing/subscribe', ...);
});
```

**Compliance Requirements:**
```php
// PCI-DSS, HIPAA, SOC2 may require multi-factor for certain operations
Route::middleware(['auth', 'multi-factor.required'])->group(function () {
    Route::get('/patient-records', ...);
    Route::get('/payment-data', ...);
});
```

## Sudo Mode Middleware

Requires users to re-verify their password before sensitive actions, even when already logged in.

### Usage

```php
// Protect sensitive routes
Route::middleware(['auth', 'sudo'])->group(function () {
    Route::delete('/account', ...);
    Route::post('/api-keys', ...);
    Route::put('/password', ...);
});

// Individual route
Route::delete('/account', [AccountController::class, 'destroy'])
    ->middleware(['auth', 'sudo']);
```

### Configuration

```php
'sudo_mode' => [
    'enabled' => true,
    'duration' => 7200, // 2 hours
    'session_key' => 'sentinel.sudo_mode_expires_at',
    'challenge_route' => 'sudo.challenge',
],
```

### Example Flow

```php
// Sudo challenge routes
Route::get('/sudo/challenge', function () {
    return view('auth.sudo-challenge');
})->name('sudo.challenge')->middleware('auth');

Route::post('/sudo/confirm', function (Request $request) {
    $request->validate(['password' => 'required']);

    if (!Hash::check($request->input('password'), $request->user()->password)) {
        return back()->withErrors(['password' => 'Incorrect password.']);
    }

    Sentinel::enableSudoMode($request);
    return redirect()->intended('/dashboard');
})->name('sudo.confirm')->middleware('auth');

// Protected route
Route::delete('/account', function (Request $request) {
    $request->user()->delete();
    Auth::logout();
    return redirect('/');
})->middleware(['auth', 'sudo']);
```

See [Sudo Mode](sudo-mode.md) for detailed documentation.

## Combining Middleware

### Full multi-factor Protection

Require multi-factor to be enabled AND completed:

```php
Route::middleware(['auth', 'multi-factor.required', 'multi-factor.complete'])->group(function () {
    Route::get('/admin/dashboard', ...);
});
```

### multi-factor + Sudo Mode

Require both multi-factor and password re-verification:

```php
Route::middleware(['auth', 'multi-factor.complete', 'sudo'])->group(function () {
    Route::delete('/admin/users/{user}', ...);
    Route::post('/admin/system/reset', ...);
});
```

### Layered Security

```php
// Public routes - no auth required
Route::get('/', ...);

// Authenticated routes
Route::middleware(['auth'])->group(function () {
    Route::get('/profile', ...);

    // multi-factor must be completed if enabled
    Route::middleware(['multi-factor.complete'])->group(function () {
        Route::get('/dashboard', ...);
        Route::get('/settings', ...);

        // Admin must have multi-factor enabled
        Route::middleware(['multi-factor.required'])->prefix('admin')->group(function () {
            Route::get('/', ...);

            // Sensitive admin actions require sudo
            Route::middleware(['sudo'])->group(function () {
                Route::delete('/users/{user}', ...);
                Route::post('/system/maintenance', ...);
            });
        });
    });
});
```

## Custom Redirects

### Override Redirect URLs

You can customize where users are redirected:

```php
// In a service provider
use Cline\Sentinel\Http\Middleware\EnsureMfaComplete;
use Cline\Sentinel\Http\Middleware\EnsureMfaEnabled;

public function boot()
{
    // Override multi-factor challenge redirect
    EnsureMfaComplete::redirectUsing(function (Request $request) {
        return route('custom.mfa.challenge');
    });

    // Override multi-factor setup redirect
    EnsureMfaEnabled::redirectUsing(function (Request $request) {
        return route('custom.mfa.setup');
    });
}
```

### Conditional Redirects

```php
EnsureMfaEnabled::redirectUsing(function (Request $request) {
    if ($request->user()->isAdmin()) {
        return route('admin.mfa.setup');
    }

    return route('user.mfa.setup');
});
```

## Excluding Routes

### Exclude from multi-factor Complete

Allow specific routes to bypass multi-factor completion:

```php
Route::middleware(['auth'])->group(function () {
    // These routes don't require multi-factor completion
    Route::get('/help', ...);
    Route::get('/mfa/setup', ...)->name('mfa.setup');
    Route::post('/mfa/verify', ...)->name('mfa.verify');

    // These routes require multi-factor completion if enabled
    Route::middleware(['multi-factor.complete'])->group(function () {
        Route::get('/dashboard', ...);
    });
});
```

## Rate Limiting

Combine with Laravel's rate limiting:

```php
Route::middleware(['auth', 'multi-factor.complete', 'throttle:60,1'])->group(function () {
    Route::post('/api/data', ...);
});
```

For sudo confirmation:

```php
Route::post('/sudo/confirm', [SudoController::class, 'confirm'])
    ->middleware(['auth', 'throttle:5,1']); // 5 attempts per minute
```

## API Routes

Protect API routes with multi-factor:

```php
// routes/api.php
Route::middleware(['auth:sanctum', 'multi-factor.complete'])->group(function () {
    Route::get('/user', ...);
    Route::get('/posts', ...);

    // Sensitive API operations
    Route::middleware(['multi-factor.required'])->group(function () {
        Route::delete('/account', ...);
        Route::post('/api-keys', ...);
    });
});
```

## Testing

### Disable Middleware in Tests

```php
use Tests\TestCase;

class FeatureTest extends TestCase
{
    public function test_dashboard_access()
    {
        $this->withoutMiddleware([
            \Cline\Sentinel\Http\Middleware\EnsureMfaComplete::class,
        ]);

        $user = User::factory()->create();

        $this->actingAs($user)
            ->get('/dashboard')
            ->assertOk();
    }
}
```

### Test multi-factor Flow

```php
public function test_mfa_required_redirects_to_setup()
{
    $user = User::factory()->create();

    $this->actingAs($user)
        ->get('/admin')
        ->assertRedirect(route('mfa.setup'));
}

public function test_user_with_mfa_can_access_admin()
{
    $user = User::factory()->create();
    createTotpCredential($user);

    $request = Request::create('/admin');
    $request->setLaravelSession(session()->driver());

    Sentinel::initiateMfaChallenge($request, $user);
    Sentinel::markMfaComplete($request);

    $this->actingAs($user)
        ->get('/admin')
        ->assertOk();
}
```

## Best Practices

1. **Always use with `auth` middleware** - multi-factor middleware requires authenticated users
2. **Order matters** - Place `auth` first, then `multi-factor.complete`, then `sudo`
3. **Don't protect multi-factor routes** - Don't apply `multi-factor.complete` to challenge/setup routes
4. **Use `multi-factor.required` for high-security areas** - Force multi-factor for admin/financial operations
5. **Combine with rate limiting** - Prevent brute force on multi-factor/sudo verification
6. **Test redirect flows** - Ensure users can complete multi-factor/sudo challenges
7. **Document requirements** - Make it clear which routes require multi-factor

## Troubleshooting

### Redirect Loop

If you get a redirect loop, ensure multi-factor routes aren't protected:

```php
// WRONG - creates redirect loop
Route::get('/mfa/challenge', ...)->middleware(['auth', 'multi-factor.complete']);

// CORRECT - only auth required
Route::get('/mfa/challenge', ...)->middleware(['auth']);
```

### Users Can't Access Routes

Check if multi-factor is completed in session:

```php
dd(
    Sentinel::getChallengedUser(request()),
    Sentinel::hasMfaCompleted(request())
);
```

### Sudo Mode Not Working

Verify sudo mode session:

```php
dd(
    Sentinel::inSudoMode(request()),
    Sentinel::sudoModeExpiresAt(request())
);
```

## Complete Example

Full application middleware setup:

```php
// routes/web.php
use Illuminate\Support\Facades\Route;

// Public routes
Route::get('/', fn() => view('welcome'));
Route::get('/login', [LoginController::class, 'show'])->name('login');
Route::post('/login', [LoginController::class, 'authenticate']);

// Authenticated routes
Route::middleware(['auth'])->group(function () {
    // multi-factor routes (NOT protected by multi-factor.complete)
    Route::get('/mfa/challenge', [MfaController::class, 'show'])
        ->name('mfa.challenge');
    Route::post('/mfa/verify', [MfaController::class, 'verify'])
        ->name('mfa.verify');
    Route::get('/mfa/setup', [MfaController::class, 'setup'])
        ->name('mfa.setup');

    // Sudo routes (NOT protected by sudo)
    Route::get('/sudo/challenge', [SudoController::class, 'show'])
        ->name('sudo.challenge');
    Route::post('/sudo/confirm', [SudoController::class, 'confirm'])
        ->name('sudo.confirm');

    // Standard authenticated routes
    Route::middleware(['multi-factor.complete'])->group(function () {
        Route::get('/dashboard', fn() => view('dashboard'));
        Route::get('/profile', [ProfileController::class, 'show']);

        // Settings routes
        Route::prefix('settings')->group(function () {
            Route::get('/', [SettingsController::class, 'index']);

            // Sensitive settings require sudo
            Route::middleware(['sudo'])->group(function () {
                Route::put('/password', [PasswordController::class, 'update']);
                Route::post('/mfa/disable', [MfaController::class, 'disable']);
                Route::delete('/account', [AccountController::class, 'destroy']);
            });
        });

        // Admin routes require multi-factor
        Route::middleware(['multi-factor.required'])->prefix('admin')->group(function () {
            Route::get('/', [AdminController::class, 'dashboard']);
            Route::resource('users', UserController::class);

            // Destructive admin actions require sudo
            Route::middleware(['sudo'])->group(function () {
                Route::delete('/users/{user}/force', ...);
                Route::post('/system/reset', ...);
            });
        });
    });
});
```
