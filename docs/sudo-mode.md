Sudo Mode provides an additional security layer for sensitive operations by requiring users to re-authenticate before performing critical actions, even when already logged in.

## What is Sudo Mode?

Sudo Mode is a temporary elevated privilege state that:
- Requires password re-confirmation before sensitive operations
- Lasts for a configurable duration (default: 2 hours)
- Expires automatically after inactivity
- Provides GitHub-like security for critical actions

## Configuration

Configure sudo mode in `config/sentinel.php`:

```php
'sudo_mode' => [
    'enabled' => true,
    'duration' => 7200, // Seconds (2 hours)
    'session_key' => 'sentinel.sudo_mode_expires_at',
    'challenge_route' => 'sudo.challenge',
],
```

### Configuration Options

- **duration**: How long sudo mode stays active (in seconds)
- **session_key**: Session key to store expiration timestamp
- **challenge_route**: Route to redirect to when sudo mode is required

## Basic Usage

### Protecting Routes

Use the `sudo` middleware to require sudo mode:

```php
use Illuminate\Support\Facades\Route;

// Protect individual routes
Route::delete('/account', [AccountController::class, 'destroy'])
    ->middleware(['auth', 'sudo']);

// Protect route groups
Route::middleware(['auth', 'sudo'])->group(function () {
    Route::delete('/account', ...);
    Route::post('/settings/api-keys', ...);
    Route::put('/settings/password', ...);
    Route::post('/billing/payment-method', ...);
});
```

### Enabling Sudo Mode

Verify user's password and enable sudo mode:

```php
use Cline\Sentinel\Facades\Sentinel;
use Illuminate\Support\Facades\Hash;

public function confirmPassword(Request $request)
{
    $request->validate([
        'password' => ['required', 'string'],
    ]);

    if (!Hash::check($request->input('password'), $request->user()->password)) {
        return back()->withErrors([
            'password' => 'The provided password is incorrect.',
        ]);
    }

    // Enable sudo mode
    Sentinel::enableSudoMode($request);

    // Redirect to intended action
    return redirect()->intended('/settings/security');
}
```

### Checking Sudo Mode Status

Check if user is currently in sudo mode:

```php
use Cline\Sentinel\Facades\Sentinel;

if (Sentinel::inSudoMode($request)) {
    // User is in sudo mode - allow sensitive action
    $this->deleteAccount($user);
} else {
    // Redirect to sudo challenge
    return redirect()->route('sudo.challenge');
}
```

Get expiration time:

```php
$expiresAt = Sentinel::sudoModeExpiresAt($request);

if ($expiresAt && $expiresAt->isFuture()) {
    $minutes = now()->diffInMinutes($expiresAt);
    echo "Sudo mode active for {$minutes} more minutes";
}
```

## Sudo Challenge Flow

### Step 1: Middleware Detects Need

When user tries to access protected route:

```php
// User visits /settings/api-keys
// Sudo middleware checks if sudo mode is active
// If not, redirects to sudo.challenge route with intended URL
```

### Step 2: Show Challenge Form

Create a sudo challenge view:

```blade
<div class="sudo-challenge">
    <h2>Confirm Your Password</h2>
    <p>This action requires additional verification. Please enter your password to continue.</p>

    <form method="POST" action="{{ route('sudo.confirm') }}">
        @csrf

        <label>
            Password:
            <input type="password" name="password" required autofocus>
        </label>

        @error('password')
            <span class="error">{{ $message }}</span>
        @enderror

        <button type="submit">Confirm</button>
        <a href="{{ url()->previous() }}">Cancel</a>
    </form>
</div>
```

### Step 3: Verify and Enable

Handle the confirmation:

```php
use Cline\Sentinel\Facades\Sentinel;
use Illuminate\Support\Facades\Hash;

public function confirmSudoMode(Request $request)
{
    $request->validate([
        'password' => ['required', 'string'],
    ]);

    if (!Hash::check($request->input('password'), $request->user()->password)) {
        return back()->withErrors([
            'password' => 'Incorrect password.',
        ]);
    }

    // Enable sudo mode
    Sentinel::enableSudoMode($request);

    // Redirect to originally intended URL
    return redirect()->intended('/dashboard');
}
```

## Route Definition Example

Complete route setup for sudo mode:

```php
// Show sudo challenge form
Route::get('/sudo/challenge', function () {
    return view('auth.sudo-challenge');
})->name('sudo.challenge')->middleware('auth');

// Handle sudo confirmation
Route::post('/sudo/confirm', [SudoController::class, 'confirm'])
    ->name('sudo.confirm')
    ->middleware('auth');

// Protected routes requiring sudo
Route::middleware(['auth', 'sudo'])->group(function () {
    Route::delete('/account', [AccountController::class, 'destroy'])
        ->name('account.destroy');

    Route::post('/settings/api-keys', [ApiKeyController::class, 'store'])
        ->name('api-keys.store');

    Route::put('/settings/password', [PasswordController::class, 'update'])
        ->name('password.update');
});
```

## Common Use Cases

### 1. Account Deletion

```php
Route::delete('/account', function (Request $request) {
    // Sudo middleware already verified password
    $request->user()->delete();

    Auth::logout();

    return redirect('/')->with('status', 'Account deleted successfully.');
})->middleware(['auth', 'sudo']);
```

### 2. API Key Generation

```php
public function createApiKey(Request $request)
{
    // Sudo mode already active from middleware
    $token = $request->user()->createToken('API Token');

    return view('api-keys.created', [
        'token' => $token->plainTextToken,
    ]);
}
```

### 3. Payment Method Changes

```php
public function updatePaymentMethod(Request $request)
{
    // Sudo middleware ensures user recently confirmed password
    $request->user()->updateDefaultPaymentMethod($request->input('payment_method'));

    return back()->with('status', 'Payment method updated.');
}
```

### 4. Security Settings

```php
Route::middleware(['auth', 'sudo'])->group(function () {
    Route::post('/security/totp/disable', ...);
    Route::post('/security/sessions/revoke-all', ...);
    Route::post('/security/download-data', ...);
});
```

## Conditional Sudo Requirement

Require sudo only for specific conditions:

```php
public function updateSettings(Request $request)
{
    $user = $request->user();

    // Check if critical settings are being changed
    $criticalChange = $request->filled('email') || $request->filled('password');

    if ($criticalChange && !Sentinel::inSudoMode($request)) {
        return redirect()->route('sudo.challenge')
            ->with('intended', route('settings.update'));
    }

    // Proceed with update
    $user->update($request->validated());

    return back()->with('status', 'Settings updated.');
}
```

## Events

Sudo mode dispatches events for monitoring:

```php
use Cline\Sentinel\Events\SudoModeEnabled;
use Cline\Sentinel\Events\SudoModeChallenged;

// Log when sudo mode is activated
Event::listen(SudoModeEnabled::class, function ($event) {
    Log::info('Sudo mode enabled', [
        'user_id' => $event->user->id,
        'ip' => request()->ip(),
    ]);
});

// Track sudo challenges (potential security interest)
Event::listen(SudoModeChallenged::class, function ($event) {
    Log::info('Sudo mode challenged', [
        'user_id' => $event->user->id,
        'route' => $event->intendedUrl,
    ]);
});
```

## Rate Limiting

Protect sudo confirmation from brute force:

```php
use Illuminate\Support\Facades\RateLimiter;

public function confirmSudoMode(Request $request)
{
    $key = 'sudo-confirm:'.$request->user()->id;

    if (RateLimiter::tooManyAttempts($key, 5)) {
        $seconds = RateLimiter::availableIn($key);
        return back()->withErrors([
            'password' => "Too many attempts. Try again in {$seconds} seconds.",
        ]);
    }

    $request->validate(['password' => ['required', 'string']]);

    if (!Hash::check($request->input('password'), $request->user()->password)) {
        RateLimiter::hit($key, 300); // 5 minute lockout
        return back()->withErrors(['password' => 'Incorrect password.']);
    }

    RateLimiter::clear($key);

    Sentinel::enableSudoMode($request);

    return redirect()->intended('/dashboard');
}
```

## UI Indicators

Show sudo mode status in UI:

```blade
@if(Sentinel::inSudoMode(request()))
    <div class="alert alert-info">
        You're in sudo mode. Sensitive actions are unlocked for
        {{ now()->diffInMinutes(Sentinel::sudoModeExpiresAt(request())) }} more minutes.
    </div>
@endif
```

In settings page:

```blade
<div class="security-indicator">
    @if(Sentinel::inSudoMode(request()))
        <span class="badge badge-success">Sudo Mode Active</span>
        <small>
            Expires {{ Sentinel::sudoModeExpiresAt(request())->diffForHumans() }}
        </small>
    @else
        <span class="badge badge-secondary">Standard Access</span>
    @endif
</div>
```

## Best Practices

1. **Use for sensitive actions only** - Don't overuse or users get frustrated
2. **Configure appropriate duration** - 2 hours is good default
3. **Show clear messaging** - Explain why password is needed again
4. **Rate limit confirmations** - Prevent brute force attacks
5. **Log sudo activations** - Monitor for suspicious patterns
6. **Send notifications** - Alert on sudo mode usage (optional)
7. **Combine with multi-factor** - Layer security for admin operations

## Actions That Should Require Sudo

**Account Management:**
- Delete account
- Change email address
- Change password
- Disable multi-factor

**Financial:**
- Add/remove payment methods
- Cancel subscription
- Download invoices

**Security:**
- Generate API keys
- Revoke all sessions
- Download personal data
- Change OAuth credentials

**Administrative:**
- Transfer ownership
- Delete resources
- Bulk operations

## Complete Example

Full sudo-protected API key management:

```php
// routes/web.php
Route::middleware(['auth'])->group(function () {
    Route::get('/api-keys', [ApiKeyController::class, 'index'])
        ->name('api-keys.index');

    Route::middleware(['sudo'])->group(function () {
        Route::post('/api-keys', [ApiKeyController::class, 'store'])
            ->name('api-keys.store');

        Route::delete('/api-keys/{key}', [ApiKeyController::class, 'destroy'])
            ->name('api-keys.destroy');
    });
});

Route::get('/sudo/challenge', [SudoController::class, 'show'])
    ->name('sudo.challenge')
    ->middleware('auth');

Route::post('/sudo/confirm', [SudoController::class, 'confirm'])
    ->name('sudo.confirm')
    ->middleware('auth');

// app/Http/Controllers/ApiKeyController.php
class ApiKeyController extends Controller
{
    public function index(Request $request)
    {
        $keys = $request->user()->tokens;

        return view('api-keys.index', [
            'keys' => $keys,
            'inSudoMode' => Sentinel::inSudoMode($request),
        ]);
    }

    public function store(Request $request)
    {
        // Sudo middleware already confirmed password
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
        ]);

        $token = $request->user()->createToken($request->input('name'));

        return back()->with([
            'status' => 'API key created successfully!',
            'token' => $token->plainTextToken,
        ]);
    }

    public function destroy(Request $request, PersonalAccessToken $key)
    {
        // Sudo middleware already confirmed password
        $key->delete();

        return back()->with('status', 'API key revoked.');
    }
}

// app/Http/Controllers/SudoController.php
class SudoController extends Controller
{
    public function show()
    {
        return view('auth.sudo-challenge');
    }

    public function confirm(Request $request)
    {
        $key = 'sudo-confirm:'.$request->user()->id;

        if (RateLimiter::tooManyAttempts($key, 5)) {
            $seconds = RateLimiter::availableIn($key);
            return back()->withErrors([
                'password' => "Too many attempts. Try again in {$seconds} seconds.",
            ]);
        }

        $request->validate(['password' => ['required', 'string']]);

        if (!Hash::check($request->input('password'), $request->user()->password)) {
            RateLimiter::hit($key, 300);
            return back()->withErrors(['password' => 'Incorrect password.']);
        }

        RateLimiter::clear($key);
        Sentinel::enableSudoMode($request);

        return redirect()->intended('/api-keys');
    }
}
```
