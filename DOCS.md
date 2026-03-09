## Table of Contents

1. [Overview](#doc-docs-readme)
2. [Events](#doc-docs-events)
3. [Mfa](#doc-docs-mfa)
4. [Middleware](#doc-docs-middleware)
5. [Passkeys](#doc-docs-passkeys)
6. [Recovery Codes](#doc-docs-recovery-codes)
7. [Security Keys](#doc-docs-security-keys)
8. [Sudo Mode](#doc-docs-sudo-mode)
9. [Totp](#doc-docs-totp)
10. [Webauthn](#doc-docs-webauthn)
<a id="doc-docs-readme"></a>

A focused, reusable Multi-Factor Authentication package for Laravel applications. Provides TOTP (authenticator apps), WebAuthn/Passkeys, and recovery codes with a clean trait-based API.

## What Sentinel Does

Sentinel handles the **second factor** of authentication:

- **TOTP** credential registration and verification (Google Authenticator, Authy, etc.)
- **WebAuthn/Passkey** registration and verification (Security Keys, Touch ID, etc.)
- **Recovery code** generation and consumption
- **Sudo mode** (temporary privilege elevation)
- **Multi-factor authentication enforcement** middleware

## What Sentinel Does NOT Do

- User registration or login (use Laravel's built-in or other packages)
- Password management
- Email verification
- Session management beyond multi-factor authentication state

## Requirements

Sentinel requires PHP 8.4+ and Laravel 12+.

## Installation

Install Sentinel with composer:

```bash
composer require cline/sentinel
```

## Add the Trait

Add Sentinel's trait to your user model:

```php
use Cline\Sentinel\Concerns\HasMultiFactorAuthentication;

class User extends Authenticatable
{
    use HasMultiFactorAuthentication;
}
```

## Run Migrations

Publish and run the migrations:

```bash
php artisan vendor:publish --tag="sentinel-migrations"
php artisan migrate
```

This creates two tables:
- `multi_factor_credentials` - Stores TOTP and WebAuthn credentials
- `multi_factor_recovery_codes` - Stores hashed one-time recovery codes

## Publish Configuration (Optional)

Publish the configuration file to customize multi-factor authentication settings:

```bash
php artisan vendor:publish --tag="sentinel-config"
```

This creates `config/sentinel.php` where you can configure:
- TOTP settings (issuer, algorithm, window)
- WebAuthn relying party settings
- Recovery code count and format
- Sudo mode duration
- Session keys and routes
- Rate limiting

## Using the Facade

Whenever you use the `Sentinel` facade in your code, add this import:

```php
use Cline\Sentinel\Facades\Sentinel;
```

## Quick Start

### Enable TOTP for a User

```php
// Step 1: Begin setup (shows QR code to user)
$setup = Sentinel::totp()->beginSetup($user);
$qrCode = $setup->getQrCodeSvg();

// Step 2: User scans QR code and enters code from their app
$code = $request->input('code');
if (Sentinel::totp()->confirmSetup($user, $code)) {
    // TOTP enabled successfully
}
```

### Generate Recovery Codes

```php
$codes = Sentinel::recoveryCodes()->generate($user);
// Returns: ['XXXXX-XXXXX', 'XXXXX-XXXXX', ...] (8 codes)

// IMPORTANT: Show these to user ONCE - they can't be retrieved later
```

### Integrate with Login Flow

```php
// In your login controller
public function authenticate(Request $request)
{
    // ... validate credentials ...

    if (Sentinel::for($user)->hasMultiFactorAuth()) {
        Sentinel::initiateMultiFactorChallenge($request, $user);
        return redirect()->route('auth.multi-factor.challenge');
    }

    // No multi-factor authentication, log in directly
    Auth::login($user);
    return redirect('/dashboard');
}
```

### Verify Multi-Factor Challenge

```php
// On multi-factor challenge page
public function verify(Request $request)
{
    $user = Sentinel::getChallengedUser($request);

    // Try TOTP
    if ($request->filled('code')) {
        if (Sentinel::totp()->verify($user, $request->input('code'))) {
            Sentinel::markMultiFactorComplete($request);
            Auth::login($user);
            return redirect('/dashboard');
        }
    }

    // Try recovery code
    if ($request->filled('recovery_code')) {
        if (Sentinel::recoveryCodes()->verify($user, $request->input('recovery_code'))) {
            Sentinel::markMultiFactorComplete($request);
            Auth::login($user);
            return redirect('/dashboard');
        }
    }

    return back()->withErrors(['code' => 'Invalid code']);
}
```

## Protect Routes with Middleware

Ensure users complete multi-factor challenges:

```php
Route::middleware(['auth', 'multi-factor.complete'])->group(function () {
    Route::get('/dashboard', ...);
});
```

Require users to have multi-factor authentication enabled:

```php
Route::middleware(['auth', 'multi-factor.required'])->group(function () {
    Route::get('/admin', ...);
});
```

Require sudo mode for sensitive operations:

```php
Route::middleware(['auth', 'sudo'])->group(function () {
    Route::delete('/account', ...);
    Route::post('/settings/api-keys', ...);
});
```

## Next Steps

- [TOTP Configuration](#doc-docs-totp) - Set up authenticator app authentication
- [Recovery Codes](#doc-docs-recovery-codes) - Emergency backup access
- [WebAuthn/Passkeys](#doc-docs-webauthn) - Security key and biometric authentication
- [Sudo Mode](#doc-docs-sudo-mode) - Re-verify identity for critical actions
- [Middleware](#doc-docs-middleware) - Protect routes with multi-factor requirements
- [Events](#doc-docs-events) - Listen to multi-factor lifecycle events

<a id="doc-docs-events"></a>

Sentinel dispatches events throughout the multi-factor lifecycle, allowing you to hook into authentication flows for logging, notifications, security monitoring, and custom business logic.

## Available Events

All events are in the `Cline\Sentinel\Events` namespace.

### TOTP Events

| Event | Dispatched When | Properties |
|-------|----------------|------------|
| `TotpEnabled` | TOTP is successfully enabled | `$user` |
| `TotpDisabled` | TOTP is disabled | `$user` |

### WebAuthn Events

| Event | Dispatched When | Properties |
|-------|----------------|------------|
| `WebAuthnCredentialRegistered` | New WebAuthn credential registered | `$user`, `$credential` |
| `WebAuthnCredentialRemoved` | WebAuthn credential removed | `$user`, `$credentialId` |

### Recovery Code Events

| Event | Dispatched When | Properties |
|-------|----------------|------------|
| `RecoveryCodesGenerated` | New recovery codes generated | `$user`, `$count` |
| `RecoveryCodeUsed` | Recovery code is consumed | `$user`, `$code` |

### multi-factor Challenge Events

| Event | Dispatched When | Properties |
|-------|----------------|------------|
| `MfaChallengeInitiated` | multi-factor challenge starts | `$user` |
| `MfaChallengeCompleted` | User completes multi-factor verification | `$user`, `$method` |
| `MfaChallengeFailed` | Verification attempt fails | `$user`, `$method`, `$reason` |

### Sudo Mode Events

| Event | Dispatched When | Properties |
|-------|----------------|------------|
| `SudoModeEnabled` | Sudo mode activated | `$user`, `$expiresAt` |
| `SudoModeChallenged` | User prompted for sudo mode | `$user`, `$intendedUrl` |

## Listening to Events

### Using Event Listeners

Create a listener class:

```php
namespace App\Listeners;

use Cline\Sentinel\Events\TotpEnabled;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use App\Mail\TotpEnabledMail;

class SendTotpEnabledNotification
{
    public function handle(TotpEnabled $event): void
    {
        // Send email notification
        Mail::to($event->user)->send(new TotpEnabledMail());

        // Log for security audit
        Log::info('TOTP enabled', [
            'user_id' => $event->user->id,
            'email' => $event->user->email,
            'ip' => request()->ip(),
        ]);
    }
}
```

Register in `EventServiceProvider`:

```php
use Cline\Sentinel\Events\TotpEnabled;
use App\Listeners\SendTotpEnabledNotification;

protected $listen = [
    TotpEnabled::class => [
        SendTotpEnabledNotification::class,
    ],
];
```

### Using Closures

Listen directly in a service provider:

```php
use Illuminate\Support\Facades\Event;
use Cline\Sentinel\Events\TotpEnabled;

public function boot(): void
{
    Event::listen(TotpEnabled::class, function (TotpEnabled $event) {
        Log::info('TOTP enabled for user ' . $event->user->id);
    });
}
```

## Common Use Cases

### 1. Email Notifications

Notify users when security settings change:

```php
use Cline\Sentinel\Events\{TotpEnabled, TotpDisabled, RecoveryCodesGenerated};
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Mail;

Event::listen(TotpEnabled::class, function ($event) {
    Mail::to($event->user)->send(new \App\Mail\TotpEnabledMail());
});

Event::listen(TotpDisabled::class, function ($event) {
    Mail::to($event->user)->send(new \App\Mail\TotpDisabledMail());
});

Event::listen(RecoveryCodesGenerated::class, function ($event) {
    Mail::to($event->user)->send(new \App\Mail\RecoveryCodesGeneratedMail($event->count));
});
```

### 2. Security Logging

Track all multi-factor-related activities:

```php
use Cline\Sentinel\Events\{MfaChallengeInitiated, MfaChallengeCompleted, MfaChallengeFailed};
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;

Event::listen(MfaChallengeInitiated::class, function ($event) {
    Log::info('multi-factor challenge initiated', [
        'user_id' => $event->user->id,
        'ip' => request()->ip(),
        'user_agent' => request()->userAgent(),
    ]);
});

Event::listen(MfaChallengeCompleted::class, function ($event) {
    Log::info('multi-factor challenge completed', [
        'user_id' => $event->user->id,
        'method' => $event->method,
        'ip' => request()->ip(),
    ]);
});

Event::listen(MfaChallengeFailed::class, function ($event) {
    Log::warning('multi-factor challenge failed', [
        'user_id' => $event->user->id,
        'method' => $event->method,
        'reason' => $event->reason,
        'ip' => request()->ip(),
    ]);
});
```

### 3. Failed Attempt Monitoring

Detect potential attacks:

```php
use Cline\Sentinel\Events\MfaChallengeFailed;
use Illuminate\Support\Facades\Cache;

Event::listen(MfaChallengeFailed::class, function ($event) {
    $key = "mfa_failures:{$event->user->id}";
    $failures = Cache::increment($key);

    // Alert after 5 failed attempts
    if ($failures >= 5) {
        Mail::to($event->user)->send(new \App\Mail\SuspiciousActivityAlert());
        Log::alert('Multiple multi-factor failures', [
            'user_id' => $event->user->id,
            'failures' => $failures,
        ]);
    }

    // Expire after 1 hour
    Cache::put($key, $failures, now()->addHour());
});
```

### 4. Recovery Code Alerts

Notify when recovery codes are used (potential compromise):

```php
use Cline\Sentinel\Events\RecoveryCodeUsed;
use Cline\Sentinel\Facades\Sentinel;

Event::listen(RecoveryCodeUsed::class, function ($event) {
    $remaining = Sentinel::recoveryCodes()->remaining($event->user);

    // Send alert
    Mail::to($event->user)->send(new \App\Mail\RecoveryCodeUsedMail($remaining));

    // Log for security review
    Log::warning('Recovery code used', [
        'user_id' => $event->user->id,
        'remaining' => $remaining,
        'ip' => request()->ip(),
    ]);

    // If running low, send urgent warning
    if ($remaining <= 2) {
        Mail::to($event->user)->send(new \App\Mail\RecoveryCodesLowMail($remaining));
    }
});
```

### 5. Compliance Auditing

Track for SOC2, HIPAA, PCI-DSS compliance:

```php
use Cline\Sentinel\Events\{TotpEnabled, TotpDisabled, SudoModeEnabled};

Event::listen(TotpEnabled::class, function ($event) {
    \App\Models\AuditLog::create([
        'user_id' => $event->user->id,
        'action' => 'mfa_enabled',
        'details' => ['method' => 'totp'],
        'ip' => request()->ip(),
    ]);
});

Event::listen(TotpDisabled::class, function ($event) {
    \App\Models\AuditLog::create([
        'user_id' => $event->user->id,
        'action' => 'mfa_disabled',
        'details' => ['method' => 'totp'],
        'ip' => request()->ip(),
    ]);
});

Event::listen(SudoModeEnabled::class, function ($event) {
    \App\Models\AuditLog::create([
        'user_id' => $event->user->id,
        'action' => 'sudo_mode_enabled',
        'details' => ['expires_at' => $event->expiresAt],
        'ip' => request()->ip(),
    ]);
});
```

### 6. Slack Notifications

Alert team when multi-factor is disabled:

```php
use Cline\Sentinel\Events\TotpDisabled;
use Illuminate\Support\Facades\Http;

Event::listen(TotpDisabled::class, function ($event) {
    Http::post(config('services.slack.webhook'), [
        'text' => "⚠️ multi-factor Disabled",
        'blocks' => [
            [
                'type' => 'section',
                'text' => [
                    'type' => 'mrkdwn',
                    'text' => "*User:* {$event->user->email}\n*Action:* TOTP disabled\n*IP:* " . request()->ip(),
                ],
            ],
        ],
    ]);
});
```

### 7. Analytics Tracking

Track multi-factor adoption metrics:

```php
use Cline\Sentinel\Events\{TotpEnabled, WebAuthnCredentialRegistered};

Event::listen(TotpEnabled::class, function ($event) {
    // Track in analytics
    analytics()->track($event->user->id, 'multi-factor Enabled', [
        'method' => 'totp',
    ]);
});

Event::listen(WebAuthnCredentialRegistered::class, function ($event) {
    analytics()->track($event->user->id, 'multi-factor Enabled', [
        'method' => 'webauthn',
        'credential_name' => $event->credential->name,
    ]);
});
```

## Event Reference

### TotpEnabled

```php
namespace Cline\Sentinel\Events;

class TotpEnabled
{
    public function __construct(
        public readonly \Illuminate\Foundation\Auth\User $user,
    ) {}
}
```

**When dispatched:** After TOTP setup is confirmed and credential is saved.

**Use for:**
- Email notifications
- Audit logging
- Analytics tracking

### TotpDisabled

```php
class TotpDisabled
{
    public function __construct(
        public readonly \Illuminate\Foundation\Auth\User $user,
    ) {}
}
```

**When dispatched:** After TOTP credential is removed.

**Use for:**
- Security alerts
- Audit logging
- Reverting multi-factor-dependent features

### WebAuthnCredentialRegistered

```php
class WebAuthnCredentialRegistered
{
    public function __construct(
        public readonly \Illuminate\Foundation\Auth\User $user,
        public readonly \Cline\Sentinel\Database\Models\MfaCredential $credential,
    ) {}
}
```

**When dispatched:** After WebAuthn credential is successfully registered.

**Use for:**
- Email notifications
- Credential inventory tracking
- Device management

### WebAuthnCredentialRemoved

```php
class WebAuthnCredentialRemoved
{
    public function __construct(
        public readonly \Illuminate\Foundation\Auth\User $user,
        public readonly string $credentialId,
    ) {}
}
```

**When dispatched:** After WebAuthn credential is deleted.

**Use for:**
- Security alerts
- Audit logging

### RecoveryCodesGenerated

```php
class RecoveryCodesGenerated
{
    public function __construct(
        public readonly \Illuminate\Foundation\Auth\User $user,
        public readonly int $count,
    ) {}
}
```

**When dispatched:** After new recovery codes are generated (including regeneration).

**Use for:**
- Email notifications
- Audit logging
- Tracking code regenerations

### RecoveryCodeUsed

```php
class RecoveryCodeUsed
{
    public function __construct(
        public readonly \Illuminate\Foundation\Auth\User $user,
        public readonly string $code,
    ) {}
}
```

**When dispatched:** After a recovery code is successfully verified and marked as used.

**Use for:**
- Security alerts (potential device loss)
- Remaining code warnings
- Compromise detection

### MfaChallengeInitiated

```php
class MfaChallengeInitiated
{
    public function __construct(
        public readonly \Illuminate\Foundation\Auth\User $user,
    ) {}
}
```

**When dispatched:** When user with multi-factor enabled attempts to log in.

**Use for:**
- Login flow tracking
- Session analysis

### MfaChallengeCompleted

```php
class MfaChallengeCompleted
{
    public function __construct(
        public readonly \Illuminate\Foundation\Auth\User $user,
        public readonly string $method, // 'totp', 'webauthn', or 'recovery_code'
    ) {}
}
```

**When dispatched:** After successful multi-factor verification.

**Use for:**
- Login success tracking
- Method preference analysis
- Session logging

### MfaChallengeFailed

```php
class MfaChallengeFailed
{
    public function __construct(
        public readonly \Illuminate\Foundation\Auth\User $user,
        public readonly string $method,
        public readonly ?string $reason = null,
    ) {}
}
```

**When dispatched:** When multi-factor verification fails.

**Use for:**
- Brute force detection
- Security monitoring
- User lockouts

### SudoModeEnabled

```php
class SudoModeEnabled
{
    public function __construct(
        public readonly \Illuminate\Foundation\Auth\User $user,
        public readonly \Illuminate\Support\Carbon $expiresAt,
    ) {}
}
```

**When dispatched:** After user successfully confirms password for sudo mode.

**Use for:**
- Privileged action tracking
- Security logging
- Session analysis

### SudoModeChallenged

```php
class SudoModeChallenged
{
    public function __construct(
        public readonly \Illuminate\Foundation\Auth\User $user,
        public readonly string $intendedUrl,
    ) {}
}
```

**When dispatched:** When user is prompted to enter sudo mode.

**Use for:**
- UX analytics
- Security flow tracking

## Testing Events

### Assert Events Dispatched

```php
use Illuminate\Support\Facades\Event;
use Cline\Sentinel\Events\TotpEnabled;

public function test_totp_enabled_event_dispatched()
{
    Event::fake();

    $user = User::factory()->create();
    $setup = Sentinel::totp()->beginSetup($user);

    Sentinel::totp()->confirmSetup($user, 'valid-code');

    Event::assertDispatched(TotpEnabled::class, function ($event) use ($user) {
        return $event->user->id === $user->id;
    });
}
```

### Test Event Listeners

```php
use Illuminate\Support\Facades\Mail;
use App\Mail\TotpEnabledMail;

public function test_sends_email_when_totp_enabled()
{
    Mail::fake();

    $user = User::factory()->create();

    event(new TotpEnabled($user));

    Mail::assertSent(TotpEnabledMail::class, function ($mail) use ($user) {
        return $mail->hasTo($user->email);
    });
}
```

## Best Practices

1. **Don't block requests** - Keep event listeners fast; queue slow operations
2. **Use queued listeners** - For emails, HTTP requests, or heavy processing
3. **Log failures** - Catch exceptions in listeners to prevent breaking user flows
4. **Be specific** - Listen to exact events you need, not all events
5. **Test listeners** - Write tests for critical event handling logic
6. **Monitor performance** - Too many listeners can slow down authentication
7. **Respect privacy** - Don't log sensitive data (passwords, codes)

## Queued Event Listeners

For slow operations (emails, HTTP calls):

```php
namespace App\Listeners;

use Cline\Sentinel\Events\TotpEnabled;
use Illuminate\Contracts\Queue\ShouldQueue;

class SendTotpEnabledNotification implements ShouldQueue
{
    public function handle(TotpEnabled $event): void
    {
        Mail::to($event->user)->send(new TotpEnabledMail());
    }
}
```

Register in `EventServiceProvider`:

```php
protected $listen = [
    TotpEnabled::class => [
        SendTotpEnabledNotification::class, // Queued automatically
    ],
];
```

<a id="doc-docs-mfa"></a>

Multi-factor authentication significantly enhances account security by requiring users to verify their identity through multiple factors. Sentinel provides a complete multi-factor implementation supporting TOTP (authenticator apps), passkeys, security keys, and recovery codes.

## Overview

Sentinel's multi-factor system provides:
- **Multiple authentication methods**: TOTP, passkeys, security keys
- **Recovery mechanisms**: Recovery codes for account access
- **Flexible enforcement**: Optional or required multi-factor per user
- **Sudo mode**: Re-verification for sensitive operations
- **Session management**: multi-factor verification tracking

## Supported Methods

| Method | Description | Use Case |
|--------|-------------|----------|
| **TOTP** | Time-based one-time passwords (Google Authenticator, Authy) | Universal compatibility |
| **Passkeys** | Synced WebAuthn credentials (Touch ID, Face ID, password managers) | Modern, convenient |
| **Security Keys** | Device-bound WebAuthn (YubiKey, Titan Key) | High security, compliance |
| **Recovery Codes** | One-time backup codes | Account recovery |

## Quick Start

### 1. Configuration

Enable multi-factor methods in `config/sentinel.php`:

```php
'methods' => [
    'totp' => [
        'enabled' => true,
        'issuer' => env('SENTINEL_TOTP_ISSUER', env('APP_NAME', 'Laravel')),
        'algorithm' => 'sha1',
        'digits' => 6,
        'period' => 30,
    ],
    'passkey' => [
        'enabled' => true,
        'relying_party' => [
            'id' => env('SENTINEL_RP_ID'),
            'name' => env('SENTINEL_RP_NAME', env('APP_NAME', 'Laravel')),
        ],
    ],
    'webauthn' => [
        'enabled' => true,
        'relying_party' => [
            'id' => env('SENTINEL_RP_ID'),
            'name' => env('SENTINEL_RP_NAME', env('APP_NAME', 'Laravel')),
        ],
    ],
    'recovery_codes' => [
        'enabled' => true,
        'count' => 10,
        'length' => 10,
    ],
],
```

### 2. Environment Variables

```bash
# .env
SENTINEL_TOTP_ISSUER="My Application"
SENTINEL_RP_ID=example.com              # For WebAuthn (passkeys/security keys)
SENTINEL_RP_NAME="My Application"
```

### 3. Database Migration

The `multi_factor_credentials` table stores all multi-factor credentials:

```php
Schema::create('multi_factor_credentials', function (Blueprint $table) {
    $table->uuid('id')->primary();
    $table->foreignId('user_id')->constrained()->cascadeOnDelete();
    $table->string('type'); // 'totp', 'passkey', 'webauthn', 'recovery_codes'
    $table->string('name')->nullable();
    $table->text('secret');
    $table->timestamp('last_used_at')->nullable();
    $table->timestamps();
});
```

## Complete multi-factor Flow

### Login Flow with multi-factor Challenge

```php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Cline\Sentinel\Facades\Sentinel;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\View\View;

class LoginController extends Controller
{
    /**
     * Handle login attempt.
     */
    public function store(Request $request): RedirectResponse
    {
        $credentials = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required'],
        ]);

        // Attempt authentication with credentials
        if (!Auth::attempt($credentials, $request->boolean('remember'))) {
            return back()->withErrors([
                'email' => 'The provided credentials do not match our records.',
            ])->onlyInput('email');
        }

        $user = Auth::user();

        // Check if user has multi-factor enabled
        if (Sentinel::for($user)->hasMultiFactorAuth()) {
            // Store user ID in session and log out temporarily
            session([
                config('sentinel.session.multi_factor_challenge_user_id') => $user->id,
            ]);

            Auth::logout();

            // Redirect to multi-factor challenge page
            return redirect()->route('auth.multi-factor.challenge');
        }

        // No multi-factor required - complete login
        $request->session()->regenerate();

        return redirect()->intended(route('dashboard'));
    }

    /**
     * Show multi-factor challenge page.
     */
    public function showChallenge(): View|RedirectResponse
    {
        $userId = session(config('sentinel.session.multi_factor_challenge_user_id'));

        if (!$userId) {
            return redirect()->route('login');
        }

        $user = \App\Models\User::findOrFail($userId);

        // Get available multi-factor methods for this user
        $availableMethods = $user->multiFactorCredentials()
            ->select('type')
            ->distinct()
            ->pluck('type')
            ->toArray();

        return view('auth.multi-factor-challenge', [
            'availableMethods' => $availableMethods,
        ]);
    }

    /**
     * Complete login after successful multi-factor verification.
     */
    public function completeMfa(Request $request): RedirectResponse
    {
        $userId = session(config('sentinel.session.multi_factor_challenge_user_id'));
        $completedAt = session(config('sentinel.session.multi_factor_completed_at'));

        if (!$userId || !$completedAt) {
            return redirect()->route('login');
        }

        $user = \App\Models\User::findOrFail($userId);

        // Log the user in
        Auth::login($user, $request->boolean('remember'));

        // Clear challenge state
        session()->forget([
            config('sentinel.session.multi_factor_challenge_user_id'),
            config('sentinel.session.multi_factor_completed_at'),
        ]);

        $request->session()->regenerate();

        return redirect()->intended(route('dashboard'));
    }
}
```

### User Model Setup

Add the `HasMultiFactorAuthentication` trait to your User model:

```php
<?php

namespace App\Models;

use Cline\Sentinel\Concerns\HasMultiFactorAuthentication;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    use HasMultiFactorAuthentication;
}
```

This provides the necessary relationships:
- `$user->multiFactorCredentials()` - All multi-factor authentication credentials
- `$user->multiFactorRecoveryCodes()` - All recovery codes
- `$user->hasMultiFactorEnabled()` - Check if any multi-factor authentication method is enabled

**For checking specific methods or getting credentials, use the `Sentinel::for()` conductor:**

```php
// Check multi-factor authentication status
$hasAny = Sentinel::for($user)->hasMultiFactorAuth();
$hasTotp = Sentinel::for($user)->hasTotpEnabled();
$hasWebAuthn = Sentinel::for($user)->hasWebAuthnEnabled();
$hasRecovery = Sentinel::for($user)->hasRecoveryCodes();

// Get credentials
$totpCredential = Sentinel::for($user)->getTotpCredential();
$webAuthnCredentials = Sentinel::for($user)->getWebAuthnCredentials();
$remainingCodes = Sentinel::for($user)->remainingRecoveryCodes();

// Disable all multi-factor authentication
Sentinel::for($user)->disableAllMfa();
```

## TOTP (Authenticator App)

### Setup Controller

```php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Cline\Sentinel\Facades\Sentinel;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

class TotpSetupController extends Controller
{
    /**
     * Show TOTP setup page.
     */
    public function create(): View
    {
        $secret = Sentinel::totp()->generateSecret();

        // Store secret temporarily in session
        session([config('sentinel.session.totp_setup_secret') => $secret]);

        $qrCode = Sentinel::totp()->getQrCode(
            user: auth()->user(),
            secret: $secret,
        );

        return view('auth.totp.setup', [
            'secret' => $secret,
            'qrCode' => $qrCode,
        ]);
    }

    /**
     * Verify and enable TOTP.
     */
    public function store(Request $request): JsonResponse
    {
        $request->validate([
            'code' => ['required', 'string', 'size:6'],
        ]);

        $secret = session(config('sentinel.session.totp_setup_secret'));

        if (!$secret) {
            return response()->json([
                'message' => 'TOTP setup session expired. Please restart setup.',
            ], 422);
        }

        try {
            $credential = Sentinel::totp()->enable(
                user: $request->user(),
                secret: $secret,
                code: $request->input('code'),
            );

            session()->forget(config('sentinel.session.totp_setup_secret'));

            return response()->json([
                'message' => 'TOTP enabled successfully.',
                'credential' => [
                    'id' => $credential->id,
                    'type' => $credential->type,
                ],
            ]);
        } catch (\Cline\Sentinel\Exceptions\InvalidTotpCodeException $exception) {
            return response()->json([
                'message' => 'Invalid verification code.',
                'error' => $exception->getMessage(),
            ], 422);
        }
    }

    /**
     * Disable TOTP.
     */
    public function destroy(Request $request): JsonResponse
    {
        Sentinel::totp()->disable($request->user());

        return response()->json([
            'message' => 'TOTP disabled successfully.',
        ]);
    }
}
```

### Verification Controller

```php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Cline\Sentinel\Facades\Sentinel;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class TotpVerificationController extends Controller
{
    /**
     * Verify TOTP code during multi-factor challenge.
     */
    public function verify(Request $request): JsonResponse
    {
        $request->validate([
            'code' => ['required', 'string', 'size:6'],
        ]);

        $userId = session(config('sentinel.session.multi_factor_challenge_user_id'));

        if (!$userId) {
            return response()->json([
                'message' => 'No active multi-factor challenge.',
            ], 403);
        }

        $user = \App\Models\User::findOrFail($userId);

        try {
            Sentinel::totp()->verify($user, $request->input('code'));

            // Mark multi-factor as completed
            session([
                config('sentinel.session.multi_factor_completed_at') => now()->timestamp,
            ]);

            return response()->json([
                'message' => 'multi-factor verification successful.',
                'redirect' => route('auth.login.complete-mfa'),
            ]);
        } catch (\Cline\Sentinel\Exceptions\InvalidTotpCodeException $exception) {
            return response()->json([
                'message' => 'Invalid verification code.',
                'error' => $exception->getMessage(),
            ], 422);
        }
    }
}
```

## Recovery Codes

### Generation Controller

```php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Cline\Sentinel\Facades\Sentinel;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class RecoveryCodesController extends Controller
{
    /**
     * Generate new recovery codes.
     */
    public function store(Request $request): JsonResponse
    {
        $codes = Sentinel::recoveryCodes()->generate($request->user());

        return response()->json([
            'message' => 'Recovery codes generated successfully.',
            'codes' => $codes,
        ]);
    }

    /**
     * Regenerate recovery codes.
     */
    public function update(Request $request): JsonResponse
    {
        $codes = Sentinel::recoveryCodes()->regenerate($request->user());

        return response()->json([
            'message' => 'Recovery codes regenerated successfully.',
            'codes' => $codes,
        ]);
    }
}
```

### Verification Controller

```php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Cline\Sentinel\Facades\Sentinel;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class RecoveryCodeVerificationController extends Controller
{
    /**
     * Verify recovery code during multi-factor challenge.
     */
    public function verify(Request $request): JsonResponse
    {
        $request->validate([
            'code' => ['required', 'string'],
        ]);

        $userId = session(config('sentinel.session.multi_factor_challenge_user_id'));

        if (!$userId) {
            return response()->json([
                'message' => 'No active multi-factor challenge.',
            ], 403);
        }

        $user = \App\Models\User::findOrFail($userId);

        try {
            Sentinel::recoveryCodes()->verify(
                user: $user,
                code: $request->input('code'),
            );

            // Mark multi-factor as completed
            session([
                config('sentinel.session.multi_factor_completed_at') => now()->timestamp,
            ]);

            return response()->json([
                'message' => 'Recovery code verified successfully.',
                'redirect' => route('auth.login.complete-mfa'),
                'warning' => 'You have used a recovery code. Consider regenerating your codes.',
            ]);
        } catch (\Cline\Sentinel\Exceptions\InvalidRecoveryCodeException $exception) {
            return response()->json([
                'message' => 'Invalid recovery code.',
                'error' => $exception->getMessage(),
            ], 422);
        }
    }
}
```

## Routes

Complete route definitions for all multi-factor flows:

```php
<?php

use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\Auth\RecoveryCodesController;
use App\Http\Controllers\Auth\RecoveryCodeVerificationController;
use App\Http\Controllers\Auth\SecurityKeyAuthenticationController;
use App\Http\Controllers\Auth\SecurityKeyRegistrationController;
use App\Http\Controllers\Auth\PasskeyAuthenticationController;
use App\Http\Controllers\Auth\PasskeyRegistrationController;
use App\Http\Controllers\Auth\TotpSetupController;
use App\Http\Controllers\Auth\TotpVerificationController;
use Illuminate\Support\Facades\Route;

// Guest routes (login flow)
Route::middleware(['guest'])->group(function () {
    // Login
    Route::post('/login', [LoginController::class, 'store'])
        ->name('login');

    // multi-factor Challenge
    Route::get('/auth/multi-factor', [LoginController::class, 'showChallenge'])
        ->name('auth.multi-factor.challenge');

    Route::post('/auth/multi-factor/complete', [LoginController::class, 'completeMfa'])
        ->name('auth.login.complete-mfa');

    // TOTP Verification
    Route::post('/auth/multi-factor/totp/verify', [TotpVerificationController::class, 'verify'])
        ->name('auth.multi-factor.totp.verify');

    // Passkey Authentication
    Route::post('/auth/multi-factor/passkey/options', [PasskeyAuthenticationController::class, 'options'])
        ->name('auth.multi-factor.passkey.options');

    Route::post('/auth/multi-factor/passkey/verify', [PasskeyAuthenticationController::class, 'verify'])
        ->name('auth.multi-factor.passkey.verify');

    // Security Key Authentication
    Route::post('/auth/multi-factor/security-key/options', [SecurityKeyAuthenticationController::class, 'options'])
        ->name('auth.multi-factor.security-key.options');

    Route::post('/auth/multi-factor/security-key/verify', [SecurityKeyAuthenticationController::class, 'verify'])
        ->name('auth.multi-factor.security-key.verify');

    // Recovery Code Verification
    Route::post('/auth/multi-factor/recovery-code/verify', [RecoveryCodeVerificationController::class, 'verify'])
        ->name('auth.multi-factor.recovery-code.verify');
});

// Authenticated routes (multi-factor management)
Route::middleware(['auth'])->group(function () {
    // TOTP Setup
    Route::get('/auth/totp/setup', [TotpSetupController::class, 'create'])
        ->name('auth.totp.setup');

    Route::post('/auth/totp/enable', [TotpSetupController::class, 'store'])
        ->name('auth.totp.enable');

    Route::delete('/auth/totp', [TotpSetupController::class, 'destroy'])
        ->name('auth.totp.destroy');

    // Passkey Registration
    Route::post('/auth/passkeys/options', [PasskeyRegistrationController::class, 'options'])
        ->name('auth.passkeys.options');

    Route::post('/auth/passkeys/verify', [PasskeyRegistrationController::class, 'verify'])
        ->name('auth.passkeys.verify');

    Route::delete('/auth/passkeys/{credential}', [PasskeyRegistrationController::class, 'destroy'])
        ->name('auth.passkeys.destroy');

    // Security Key Registration
    Route::post('/auth/security-keys/options', [SecurityKeyRegistrationController::class, 'options'])
        ->name('auth.security-keys.options');

    Route::post('/auth/security-keys/verify', [SecurityKeyRegistrationController::class, 'verify'])
        ->name('auth.security-keys.verify');

    Route::delete('/auth/security-keys/{credential}', [SecurityKeyRegistrationController::class, 'destroy'])
        ->name('auth.security-keys.destroy');

    // Recovery Codes
    Route::post('/auth/recovery-codes', [RecoveryCodesController::class, 'store'])
        ->name('auth.recovery-codes.generate');

    Route::put('/auth/recovery-codes', [RecoveryCodesController::class, 'update'])
        ->name('auth.recovery-codes.regenerate');
});
```

## Frontend Implementation

### multi-factor Challenge Page

Create `resources/views/auth/multi-factor-challenge.blade.php`:

```blade
<x-guest-layout>
    <div class="max-w-md mx-auto">
        <h2 class="text-2xl font-bold mb-6">Two-Factor Authentication</h2>
        <p class="text-gray-600 mb-8">Choose a verification method to continue:</p>

        <div class="space-y-4">
            @if(in_array('totp', $availableMethods))
                <div x-data="{ open: false }">
                    <button
                        @click="open = !open"
                        class="w-full flex items-center justify-between p-4 border rounded-lg hover:bg-gray-50"
                    >
                        <div class="flex items-center gap-3">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                            </svg>
                            <span class="font-medium">Authenticator App</span>
                        </div>
                        <svg class="w-5 h-5 transform transition-transform" :class="{ 'rotate-180': open }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                        </svg>
                    </button>

                    <div x-show="open" x-cloak class="mt-2 p-4 border rounded-lg">
                        @include('auth.partials.totp-challenge')
                    </div>
                </div>
            @endif

            @if(in_array('passkey', $availableMethods))
                <div x-data="{ open: false }">
                    <button
                        @click="open = !open"
                        class="w-full flex items-center justify-between p-4 border rounded-lg hover:bg-gray-50"
                    >
                        <div class="flex items-center gap-3">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                            </svg>
                            <span class="font-medium">Passkey</span>
                        </div>
                        <svg class="w-5 h-5 transform transition-transform" :class="{ 'rotate-180': open }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                        </svg>
                    </button>

                    <div x-show="open" x-cloak class="mt-2 p-4 border rounded-lg">
                        @include('auth.partials.passkey-challenge')
                    </div>
                </div>
            @endif

            @if(in_array('webauthn', $availableMethods))
                <div x-data="{ open: false }">
                    <button
                        @click="open = !open"
                        class="w-full flex items-center justify-between p-4 border rounded-lg hover:bg-gray-50"
                    >
                        <div class="flex items-center gap-3">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                            </svg>
                            <span class="font-medium">Security Key</span>
                        </div>
                        <svg class="w-5 h-5 transform transition-transform" :class="{ 'rotate-180': open }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                        </svg>
                    </button>

                    <div x-show="open" x-cloak class="mt-2 p-4 border rounded-lg">
                        @include('auth.partials.security-key-challenge')
                    </div>
                </div>
            @endif

            <!-- Recovery Code Option -->
            <div x-data="{ open: false }">
                <button
                    @click="open = !open"
                    class="w-full flex items-center justify-between p-4 border rounded-lg hover:bg-gray-50"
                >
                    <div class="flex items-center gap-3">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                        <span class="font-medium">Recovery Code</span>
                    </div>
                    <svg class="w-5 h-5 transform transition-transform" :class="{ 'rotate-180': open }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                    </svg>
                </button>

                <div x-show="open" x-cloak class="mt-2 p-4 border rounded-lg">
                    @include('auth.partials.recovery-code-challenge')
                </div>
            </div>
        </div>
    </div>
</x-guest-layout>
```

### TOTP Challenge Partial

Create `resources/views/auth/partials/totp-challenge.blade.php`:

```blade
<div x-data="totpChallenge()">
    <form @submit.prevent="verify">
        <label for="totp-code" class="block text-sm font-medium text-gray-700 mb-2">
            Enter the 6-digit code from your authenticator app:
        </label>
        <input
            type="text"
            id="totp-code"
            x-model="code"
            maxlength="6"
            pattern="[0-9]{6}"
            inputmode="numeric"
            autocomplete="one-time-code"
            class="w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200"
            :disabled="verifying"
        />

        <button
            type="submit"
            :disabled="verifying || code.length !== 6"
            class="mt-4 w-full px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
            x-text="verifying ? 'Verifying...' : 'Verify Code'"
        ></button>

        <div x-show="error" class="mt-4 bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded">
            <p x-text="error"></p>
        </div>
    </form>
</div>

<script>
function totpChallenge() {
    return {
        code: '',
        verifying: false,
        error: null,

        async verify() {
            this.verifying = true;
            this.error = null;

            try {
                const response = await fetch('{{ route("auth.multi-factor.totp.verify") }}', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
                    },
                    body: JSON.stringify({ code: this.code }),
                });

                const result = await response.json();

                if (!response.ok) {
                    throw new Error(result.message || 'Verification failed');
                }

                // Redirect to complete multi-factor flow
                window.location.href = result.redirect;

            } catch (err) {
                this.error = err.message;
                this.code = '';
            } finally {
                this.verifying = false;
            }
        },
    };
}
</script>
```

### Recovery Code Challenge Partial

Create `resources/views/auth/partials/recovery-code-challenge.blade.php`:

```blade
<div x-data="recoveryCodeChallenge()">
    <form @submit.prevent="verify">
        <label for="recovery-code" class="block text-sm font-medium text-gray-700 mb-2">
            Enter one of your recovery codes:
        </label>
        <input
            type="text"
            id="recovery-code"
            x-model="code"
            placeholder="xxxx-xxxx-xxxx"
            class="w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200"
            :disabled="verifying"
        />

        <p class="mt-2 text-sm text-gray-500">
            Each recovery code can only be used once. Make sure to regenerate new codes after using one.
        </p>

        <button
            type="submit"
            :disabled="verifying || !code.trim()"
            class="mt-4 w-full px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
            x-text="verifying ? 'Verifying...' : 'Verify Code'"
        ></button>

        <div x-show="error" class="mt-4 bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded">
            <p x-text="error"></p>
        </div>
    </form>
</div>

<script>
function recoveryCodeChallenge() {
    return {
        code: '',
        verifying: false,
        error: null,

        async verify() {
            this.verifying = true;
            this.error = null;

            try {
                const response = await fetch('{{ route("auth.multi-factor.recovery-code.verify") }}', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
                    },
                    body: JSON.stringify({ code: this.code }),
                });

                const result = await response.json();

                if (!response.ok) {
                    throw new Error(result.message || 'Verification failed');
                }

                // Redirect to complete multi-factor flow
                window.location.href = result.redirect;

            } catch (err) {
                this.error = err.message;
                this.code = '';
            } finally {
                this.verifying = false;
            }
        },
    };
}
</script>
```

## Enforcement Strategies

### Optional Multi-Factor Authentication

Allow users to enable multi-factor voluntarily:

```php
// User settings page
Route::get('/settings/security', [SecuritySettingsController::class, 'index'])
    ->middleware('auth')
    ->name('settings.security');
```

### Required Multi-Factor Authentication

Force all users to enable multi-factor authentication:

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class RequireMfa
{
    public function handle(Request $request, Closure $next)
    {
        $user = $request->user();

        if ($user && !Sentinel::for($user)->hasMultiFactorAuth()) {
            return redirect()->route('auth.mfa.setup')
                ->with('warning', 'You must enable two-factor authentication to continue.');
        }

        return $next($request);
    }
}
```

Apply to routes:

```php
Route::middleware(['auth', 'require-mfa'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index']);
    // ...
});
```

### Role-Based Multi-Factor Authentication

Require multi-factor for specific roles:

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class RequireMfaForAdmins
{
    public function handle(Request $request, Closure $next)
    {
        $user = $request->user();

        if ($user && $user->hasRole('admin') && !Sentinel::for($user)->hasMultiFactorAuth()) {
            return redirect()->route('auth.mfa.setup')
                ->with('warning', 'Administrators must enable two-factor authentication.');
        }

        return $next($request);
    }
}
```

## Sudo Mode

Require re-verification for sensitive operations:

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class RequireSudoMode
{
    public function handle(Request $request, Closure $next)
    {
        $confirmedAt = session(config('sentinel.session.sudo_confirmed_at'));

        // Check if sudo mode was confirmed within last 3 hours
        if (!$confirmedAt || now()->timestamp - $confirmedAt > 10800) {
            return redirect()->route('auth.sudo.confirm')
                ->with('intended', $request->url());
        }

        return $next($request);
    }
}
```

Apply to sensitive routes:

```php
Route::middleware(['auth', 'sudo'])->group(function () {
    Route::delete('/account', [AccountController::class, 'destroy']);
    Route::put('/account/email', [AccountController::class, 'updateEmail']);
    Route::post('/billing/subscription', [BillingController::class, 'subscribe']);
});
```

## Testing

### Feature Tests

```php
<?php

use App\Models\User;
use Cline\Sentinel\Database\Models\MultiFactorCredential;

test('user with multi-factor enabled is challenged during login', function () {
    $user = User::factory()->create();

    MultiFactorCredential::factory()->create([
        'user_id' => $user->id,
        'type' => 'totp',
    ]);

    $response = $this->post(route('login'), [
        'email' => $user->email,
        'password' => 'password',
    ]);

    $response->assertRedirect(route('auth.multi-factor.challenge'));

    expect(session(config('sentinel.session.multi_factor_challenge_user_id')))
        ->toBe($user->id);
});

test('user without multi-factor logs in directly', function () {
    $user = User::factory()->create();

    $response = $this->post(route('login'), [
        'email' => $user->email,
        'password' => 'password',
    ]);

    $response->assertRedirect(route('dashboard'));
    $this->assertAuthenticatedAs($user);
});

test('user can complete login after multi-factor verification', function () {
    $user = User::factory()->create();

    session([
        config('sentinel.session.multi_factor_challenge_user_id') => $user->id,
        config('sentinel.session.multi_factor_completed_at') => now()->timestamp,
    ]);

    $response = $this->post(route('auth.login.complete-mfa'));

    $response->assertRedirect(route('dashboard'));
    $this->assertAuthenticatedAs($user);
});
```

## Best Practices

### 1. Recovery Code Management

Always generate recovery codes when enabling first multi-factor method:

```php
if (!Sentinel::for($user)->hasMultiFactorAuth() && !Sentinel::for($user)->hasRecoveryCodes()) {
    $codes = Sentinel::recoveryCodes()->generate($user);

    // Show codes to user ONCE
    return view('auth.recovery-codes.show', ['codes' => $codes]);
}
```

### 2. Multiple multi-factor Methods

Encourage users to register backup methods:

```php
$mfaMethodCount = $user->multiFactorCredentials()
    ->whereIn('type', ['totp', 'passkey', 'webauthn'])
    ->count();

if ($mfaMethodCount === 1) {
    // Show recommendation to add backup method
}
```

### 3. Session Security

Regenerate session after multi-factor completion:

```php
Auth::login($user);
$request->session()->regenerate();
```

### 4. Rate Limiting

Protect multi-factor endpoints from brute force:

```php
Route::post('/auth/multi-factor/totp/verify', [TotpVerificationController::class, 'verify'])
    ->middleware('throttle:5,1'); // 5 attempts per minute
```

## Troubleshooting

### multi-factor challenge loop

**Cause**: Session state not cleared after failed login.

**Solution**:
```php
// Clear stale challenge state
session()->forget([
    config('sentinel.session.multi_factor_challenge_user_id'),
    config('sentinel.session.multi_factor_completed_at'),
]);
```

### Recovery codes not working

**Cause**: Codes are case-sensitive and include hyphens.

**Solution**: Normalize input:
```php
$code = strtoupper(trim($request->input('code')));
```

### Users locked out

**Cause**: Lost access to all multi-factor methods.

**Solution**: Implement admin override:
```php
// Admin can disable multi-factor for locked-out user
public function disableMfa(User $user)
{
    $user->multiFactorCredentials()->delete();

    Log::info('multi-factor disabled by admin', ['user_id' => $user->id, 'admin_id' => auth()->id()]);
}
```

## Related Documentation

- [Passkeys Integration](#doc-docs-passkeys) - Synced WebAuthn credentials
- [Security Keys Integration](#doc-docs-security-keys) - Device-bound credentials
- [TOTP Setup](#doc-docs-totp) - Authenticator app configuration
- [Events](#doc-docs-events) - multi-factor event handling
- [Testing](#) - Comprehensive test examples

## External Resources

- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/) - multi-factor standards
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [WebAuthn Guide](https://webauthn.guide/) - Interactive tutorial
- [Google Authenticator](https://support.google.com/accounts/answer/1066447) - TOTP setup

<a id="doc-docs-middleware"></a>

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

See [Sudo Mode](#doc-docs-sudo-mode) for detailed documentation.

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

<a id="doc-docs-passkeys"></a>

Passkeys provide passwordless authentication with credentials that sync across a user's devices via iCloud Keychain, Google Password Manager, 1Password, and other password managers. This guide provides production-ready code for integrating passkey support.

## What Are Passkeys?

Passkeys are WebAuthn credentials with these key characteristics:

- **Synced across devices**: Stored in cloud password managers
- **No passwords**: Users authenticate with biometrics or device PIN
- **Phishing-resistant**: Cryptographic verification prevents credential theft
- **Platform-managed**: OS handles security and sync

## Quick Start

### 1. Configuration

```php
// config/sentinel.php
'methods' => [
    'passkey' => [
        'enabled' => true,
        'relying_party' => [
            'id' => env('SENTINEL_RP_ID'), // e.g., 'example.com'
            'name' => env('SENTINEL_RP_NAME', env('APP_NAME')),
        ],
    ],
],
```

### 2. Environment Variables

```bash
# .env
SENTINEL_RP_ID=example.com
SENTINEL_RP_NAME="My Application"
```

**Important**: `SENTINEL_RP_ID` must match your domain exactly (no protocol, no port).

## Complete Controller Implementation

### Registration Controller

```php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Cline\Sentinel\Facades\Sentinel;
use Cline\Sentinel\Exceptions\InvalidWebAuthnAssertionException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class PasskeyRegistrationController extends Controller
{
    /**
     * Generate passkey registration options.
     */
    public function options(Request $request): JsonResponse
    {
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
        ]);

        // Generate WebAuthn registration options for passkey (synced credential)
        $options = Sentinel::webAuthn()->beginRegistration(
            user: $request->user(),
            asPasskey: true, // Important: true for passkeys, false for security keys
        );

        // Store options in session for verification
        session([
            config('sentinel.session.webauthn_registration_options') => $options,
        ]);

        return response()->json([
            'options' => json_decode($options, true),
        ]);
    }

    /**
     * Verify and store passkey registration.
     */
    public function verify(Request $request): JsonResponse
    {
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'credential' => ['required', 'string'], // JSON from browser
        ]);

        $options = session(config('sentinel.session.webauthn_registration_options'));

        if (!$options) {
            throw ValidationException::withMessages([
                'credential' => ['Registration session expired. Please try again.'],
            ]);
        }

        try {
            $credential = Sentinel::webAuthn()->confirmRegistration(
                user: $request->user(),
                credentialJson: $request->input('credential'),
                optionsJson: $options,
                hostname: $request->getHost(),
                name: $request->input('name'),
                type: 'passkey', // Mark as passkey for UX differentiation
            );

            session()->forget(config('sentinel.session.webauthn_registration_options'));

            return response()->json([
                'success' => true,
                'credential' => [
                    'id' => $credential->id,
                    'name' => $credential->name,
                    'created_at' => $credential->created_at,
                ],
            ]);
        } catch (InvalidWebAuthnAssertionException $e) {
            throw ValidationException::withMessages([
                'credential' => [$e->getMessage()],
            ]);
        }
    }

    /**
     * Remove a passkey.
     */
    public function destroy(Request $request, string $credentialId): JsonResponse
    {
        $credential = $request->user()
            ->mfaCredentials()
            ->where('id', $credentialId)
            ->where('type', 'passkey')
            ->firstOrFail();

        Sentinel::webAuthn()->remove($request->user(), $credentialId);

        return response()->json(['success' => true]);
    }
}
```

### Authentication Controller (multi-factor Challenge)

```php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Cline\Sentinel\Facades\Sentinel;
use Cline\Sentinel\Exceptions\InvalidWebAuthnAssertionException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

class PasskeyAuthenticationController extends Controller
{
    /**
     * Generate passkey authentication options.
     */
    public function options(Request $request): JsonResponse
    {
        // Get user from multi-factor challenge session
        $userId = session(config('sentinel.session.multi_factor_challenge_user_id'));

        if (!$userId) {
            throw ValidationException::withMessages([
                'credential' => ['Authentication session not found.'],
            ]);
        }

        $user = Auth::getProvider()->retrieveById($userId);

        // Generate authentication challenge
        $options = Sentinel::webAuthn()->beginAuthentication($user);

        // Store options for verification
        session([
            config('sentinel.session.webauthn_authentication_options') => $options,
        ]);

        return response()->json([
            'options' => json_decode($options, true),
        ]);
    }

    /**
     * Verify passkey authentication.
     */
    public function verify(Request $request): JsonResponse
    {
        $request->validate([
            'credential' => ['required', 'string'], // JSON from browser
        ]);

        $options = session(config('sentinel.session.webauthn_authentication_options'));

        if (!$options) {
            throw ValidationException::withMessages([
                'credential' => ['Authentication session expired. Please try again.'],
            ]);
        }

        try {
            // Verify the assertion
            $credential = Sentinel::webAuthn()->verify(
                credentialJson: $request->input('credential'),
                optionsJson: $options,
                hostname: $request->getHost(),
            );

            // Mark multi-factor as complete
            Sentinel::markMfaComplete($request);

            // Clean up session
            session()->forget(config('sentinel.session.webauthn_authentication_options'));

            // Log the user in
            Auth::loginUsingId($credential->user_id);

            return response()->json([
                'success' => true,
                'redirect' => route('dashboard'),
            ]);
        } catch (InvalidWebAuthnAssertionException $e) {
            throw ValidationException::withMessages([
                'credential' => ['Authentication failed. Please try again.'],
            ]);
        }
    }
}
```

## Routes

```php
// routes/web.php

use App\Http\Controllers\Auth\PasskeyRegistrationController;
use App\Http\Controllers\Auth\PasskeyAuthenticationController;

// Passkey registration (authenticated users only)
Route::middleware(['auth'])->group(function () {
    Route::post('/passkeys/register/options', [PasskeyRegistrationController::class, 'options'])
        ->name('passkeys.register.options');
    Route::post('/passkeys/register/verify', [PasskeyRegistrationController::class, 'verify'])
        ->name('passkeys.register.verify');
    Route::delete('/passkeys/{credentialId}', [PasskeyRegistrationController::class, 'destroy'])
        ->name('passkeys.destroy');
});

// Passkey authentication (during multi-factor challenge)
Route::middleware(['guest'])->group(function () {
    Route::post('/auth/passkey/options', [PasskeyAuthenticationController::class, 'options'])
        ->name('passkeys.auth.options');
    Route::post('/auth/passkey/verify', [PasskeyAuthenticationController::class, 'verify'])
        ->name('passkeys.auth.verify');
});
```

## Frontend Implementation

### Registration Component (Livewire)

```php
<?php

namespace App\Livewire\Settings;

use Livewire\Component;
use Livewire\Attributes\On;

class ManagePasskeys extends Component
{
    public string $name = '';
    public bool $isRegistering = false;

    public function render()
    {
        return view('livewire.settings.manage-passkeys', [
            'passkeys' => auth()->user()
                ->mfaCredentials()
                ->where('type', 'passkey')
                ->latest()
                ->get(),
        ]);
    }

    #[On('passkey-registered')]
    public function passkeyRegistered(): void
    {
        $this->reset('name', 'isRegistering');
        $this->dispatch('notify', message: 'Passkey registered successfully!');
    }

    public function deletePasskey(string $id): void
    {
        // Deletion handled via Alpine.js to avoid page refresh
    }
}
```

### Registration Blade View

```blade
<div x-data="passkeyRegistration" class="space-y-6">
    <!-- List existing passkeys -->
    <div>
        <h3 class="text-lg font-medium">Your Passkeys</h3>

        @forelse($passkeys as $passkey)
            <div class="flex items-center justify-between py-3 border-b">
                <div>
                    <p class="font-medium">{{ $passkey->name }}</p>
                    <p class="text-sm text-gray-600">
                        Added {{ $passkey->created_at->diffForHumans() }}
                        @if($passkey->last_used_at)
                            • Last used {{ $passkey->last_used_at->diffForHumans() }}
                        @endif
                    </p>
                </div>
                <button
                    type="button"
                    @click="deletePasskey('{{ $passkey->id }}')"
                    class="text-red-600 hover:text-red-800"
                >
                    Remove
                </button>
            </div>
        @empty
            <p class="text-gray-600 py-4">No passkeys registered yet.</p>
        @endforelse
    </div>

    <!-- Add new passkey -->
    <div>
        <form wire:submit.prevent @submit="register">
            <div class="space-y-4">
                <div>
                    <label for="passkey-name" class="block text-sm font-medium">
                        Passkey Name
                    </label>
                    <input
                        type="text"
                        id="passkey-name"
                        wire:model="name"
                        x-model="name"
                        placeholder="e.g., MacBook Touch ID"
                        class="mt-1 block w-full rounded-md border-gray-300"
                        required
                    >
                </div>

                <button
                    type="submit"
                    class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                    :disabled="registering"
                >
                    <span x-show="!registering">Add Passkey</span>
                    <span x-show="registering">Registering...</span>
                </button>
            </div>
        </form>
    </div>
</div>

@push('scripts')
<script>
document.addEventListener('alpine:init', () => {
    Alpine.data('passkeyRegistration', () => ({
        name: @entangle('name'),
        registering: false,

        async register() {
            if (!this.name.trim()) {
                alert('Please enter a name for this passkey');
                return;
            }

            this.registering = true;

            try {
                // Step 1: Get registration options from server
                const optionsResponse = await fetch('{{ route('passkeys.register.options') }}', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': '{{ csrf_token() }}',
                    },
                    body: JSON.stringify({ name: this.name }),
                });

                if (!optionsResponse.ok) {
                    throw new Error('Failed to get registration options');
                }

                const { options } = await optionsResponse.json();

                // Step 2: Convert challenge and user ID to ArrayBuffer
                options.challenge = this.base64ToBuffer(options.challenge);
                options.user.id = this.base64ToBuffer(options.user.id);

                // Step 3: Prompt user to create credential
                const credential = await navigator.credentials.create({
                    publicKey: options,
                });

                if (!credential) {
                    throw new Error('No credential created');
                }

                // Step 4: Send credential to server for verification
                const verifyResponse = await fetch('{{ route('passkeys.register.verify') }}', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': '{{ csrf_token() }}',
                    },
                    body: JSON.stringify({
                        name: this.name,
                        credential: this.credentialToJSON(credential),
                    }),
                });

                if (!verifyResponse.ok) {
                    const error = await verifyResponse.json();
                    throw new Error(error.message || 'Verification failed');
                }

                // Success!
                Livewire.dispatch('passkey-registered');
                this.$wire.$refresh();

            } catch (error) {
                console.error('Passkey registration error:', error);
                alert(error.message || 'Failed to register passkey. Please try again.');
            } finally {
                this.registering = false;
            }
        },

        async deletePasskey(id) {
            if (!confirm('Remove this passkey?')) return;

            try {
                const response = await fetch(`/passkeys/${id}`, {
                    method: 'DELETE',
                    headers: {
                        'X-CSRF-TOKEN': '{{ csrf_token() }}',
                    },
                });

                if (response.ok) {
                    this.$wire.$refresh();
                }
            } catch (error) {
                alert('Failed to remove passkey');
            }
        },

        // Helper to convert base64url to ArrayBuffer
        base64ToBuffer(base64url) {
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            const binary = atob(base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        },

        // Helper to convert ArrayBuffer to base64url
        bufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            const base64 = btoa(binary);
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        },

        // Convert PublicKeyCredential to JSON
        credentialToJSON(credential) {
            return JSON.stringify({
                id: credential.id,
                rawId: this.bufferToBase64(credential.rawId),
                response: {
                    clientDataJSON: this.bufferToBase64(credential.response.clientDataJSON),
                    attestationObject: this.bufferToBase64(credential.response.attestationObject),
                },
                type: credential.type,
            });
        },
    }));
});
</script>
@endpush
```

### Authentication Component (Alpine.js)

```blade
<div x-data="passkeyAuthentication" class="space-y-4">
    <div class="text-center">
        <button
            @click="authenticate"
            class="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            :disabled="authenticating"
        >
            <span x-show="!authenticating">Use Passkey</span>
            <span x-show="authenticating">Authenticating...</span>
        </button>
    </div>
</div>

@push('scripts')
<script>
document.addEventListener('alpine:init', () => {
    Alpine.data('passkeyAuthentication', () => ({
        authenticating: false,

        async authenticate() {
            this.authenticating = true;

            try {
                // Step 1: Get authentication options
                const optionsResponse = await fetch('{{ route('passkeys.auth.options') }}', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': '{{ csrf_token() }}',
                    },
                });

                if (!optionsResponse.ok) {
                    throw new Error('Failed to get authentication options');
                }

                const { options } = await optionsResponse.json();

                // Step 2: Convert challenge to ArrayBuffer
                options.challenge = this.base64ToBuffer(options.challenge);

                // Convert allowed credential IDs
                if (options.allowCredentials) {
                    options.allowCredentials = options.allowCredentials.map(cred => ({
                        ...cred,
                        id: this.base64ToBuffer(cred.id),
                    }));
                }

                // Step 3: Prompt user to authenticate
                const credential = await navigator.credentials.get({
                    publicKey: options,
                });

                if (!credential) {
                    throw new Error('No credential provided');
                }

                // Step 4: Send assertion to server
                const verifyResponse = await fetch('{{ route('passkeys.auth.verify') }}', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': '{{ csrf_token() }}',
                    },
                    body: JSON.stringify({
                        credential: this.assertionToJSON(credential),
                    }),
                });

                if (!verifyResponse.ok) {
                    throw new Error('Authentication failed');
                }

                const { redirect } = await verifyResponse.json();

                // Redirect to dashboard
                window.location.href = redirect;

            } catch (error) {
                console.error('Passkey authentication error:', error);
                alert(error.message || 'Authentication failed. Please try again.');
            } finally {
                this.authenticating = false;
            }
        },

        base64ToBuffer(base64url) {
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            const binary = atob(base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        },

        bufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            const base64 = btoa(binary);
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        },

        assertionToJSON(credential) {
            return JSON.stringify({
                id: credential.id,
                rawId: this.bufferToBase64(credential.rawId),
                response: {
                    clientDataJSON: this.bufferToBase64(credential.response.clientDataJSON),
                    authenticatorData: this.bufferToBase64(credential.response.authenticatorData),
                    signature: this.bufferToBase64(credential.response.signature),
                    userHandle: credential.response.userHandle
                        ? this.bufferToBase64(credential.response.userHandle)
                        : null,
                },
                type: credential.type,
            });
        },
    }));
});
</script>
@endpush
```

## Browser Compatibility Check

```blade
<div x-data="{ supported: !!window.PublicKeyCredential }" x-init="
    if (window.PublicKeyCredential) {
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
            .then(available => supported = available);
    }
">
    <div x-show="supported">
        <!-- Show passkey UI -->
    </div>
    <div x-show="!supported">
        <p>Passkeys are not supported on this device. Please use TOTP instead.</p>
    </div>
</div>
```

## Testing

### Feature Test

```php
<?php

use App\Models\User;
use Cline\Sentinel\Facades\Sentinel;
use function Pest\Laravel\actingAs;

it('can register a passkey', function () {
    $user = User::factory()->create();

    actingAs($user)
        ->post(route('passkeys.register.options'), [
            'name' => 'Test Passkey',
        ])
        ->assertOk()
        ->assertJsonStructure(['options']);

    expect(session()->has('sentinel.webauthn_registration_options'))->toBeTrue();
});

it('requires valid credential for registration', function () {
    $user = User::factory()->create();

    actingAs($user)
        ->post(route('passkeys.register.verify'), [
            'name' => 'Test Passkey',
            'credential' => 'invalid-json',
        ])
        ->assertUnprocessable();
});
```

## Troubleshooting

### Passkey Not Creating

**Check HTTPS**: Passkeys require HTTPS in production (localhost OK for dev)

**Verify RP ID**: Must match domain exactly:
```bash
# Correct
SENTINEL_RP_ID=example.com

# Wrong
SENTINEL_RP_ID=https://example.com  # No protocol
SENTINEL_RP_ID=example.com:443      # No port
```

### Cross-Origin Issues

If using subdomains, set RP ID to parent domain:
```bash
# For app.example.com and auth.example.com
SENTINEL_RP_ID=example.com
```

### Device Not Offering Passkey

Platform requirements:
- iOS 16+ (iCloud Keychain)
- Android 9+ (Google Password Manager)
- macOS 13+ (iCloud Keychain)
- Windows 10+ (Windows Hello)

## Best Practices

1. **Let users name credentials** - "MacBook Touch ID", "iPhone", etc.
2. **Show last used timestamp** - Helps users manage devices
3. **Allow multiple passkeys** - Users should have backup devices
4. **Combine with TOTP** - Offer choice for user preference
5. **Provide recovery codes** - Essential for account recovery
6. **Test across platforms** - Different OS behaviors
7. **Clear error messages** - Guide users through browser prompts

## Next Steps

- [Security Keys](#doc-docs-security-keys) - Device-bound WebAuthn credentials
- [Recovery Codes](#doc-docs-recovery-codes) - Backup authentication method
- [Events](#doc-docs-events) - Listen to passkey registration/usage

<a id="doc-docs-recovery-codes"></a>

Recovery codes provide emergency backup access when users lose access to their primary multi-factor device. They are one-time use codes that can be used instead of TOTP or WebAuthn.

## How Recovery Codes Work

1. **Generation**: Server creates 8 random codes and hashes them with bcrypt
2. **Display Once**: Codes shown to user immediately (cannot be retrieved later)
3. **Storage**: Only hashed versions are stored in database
4. **Usage**: User enters code during multi-factor challenge
5. **Consumption**: Valid codes are marked as used (one-time only)

## Generating Recovery Codes

Always generate recovery codes after enabling any multi-factor method:

```php
use Cline\Sentinel\Facades\Sentinel;

public function enableTotp(Request $request)
{
    // ... TOTP setup and confirmation ...

    // Generate recovery codes immediately
    $codes = Sentinel::recoveryCodes()->generate($request->user());

    // IMPORTANT: Show these to the user NOW - they can't be retrieved later
    return view('auth.recovery-codes', [
        'codes' => $codes,
    ]);
}
```

The `generate()` method:
- Creates 8 new codes in `XXXXX-XXXXX` format (uppercase alphanumeric)
- Invalidates any existing codes
- Returns array of plain text codes
- Stores only bcrypt hashes in database

## Displaying Recovery Codes

Show codes prominently with download/print options:

```blade
<div class="recovery-codes">
    <h2>Save Your Recovery Codes</h2>

    <div class="alert alert-warning">
        <strong>Important:</strong> Store these codes in a safe place.
        They won't be shown again and each can only be used once.
    </div>

    <div class="codes-grid">
        @foreach($codes as $code)
            <code class="recovery-code">{{ $code }}</code>
        @endforeach
    </div>

    <div class="actions">
        <button onclick="downloadCodes()">Download Codes</button>
        <button onclick="window.print()">Print Codes</button>
        <form method="POST" action="{{ route('dashboard') }}">
            @csrf
            <button type="submit">I've Saved My Codes</button>
        </form>
    </div>
</div>

<script>
function downloadCodes() {
    const codes = @json($codes);
    const text = 'Recovery Codes for {{ config('app.name') }}\n\n' +
                 codes.join('\n') +
                 '\n\nKeep these codes safe. Each can only be used once.';

    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'recovery-codes.txt';
    a.click();
}
</script>
```

## Configuration

Configure recovery code settings in `config/sentinel.php`:

```php
'recovery_codes' => [
    'enabled' => true,
    'count' => 8,           // Number of codes to generate
    'length' => 10,         // Total characters per code (excluding dash)
    'format' => 'XXXXX-XXXXX', // Display format
],
```

## Using Recovery Codes

Allow users to enter recovery codes during multi-factor challenge:

```php
use Cline\Sentinel\Facades\Sentinel;

public function verifyMfa(Request $request)
{
    $user = Sentinel::getChallengedUser($request);

    // TOTP verification
    if ($request->filled('code')) {
        if (Sentinel::totp()->verify($user, $request->input('code'))) {
            Sentinel::markMultiFactorComplete($request);
            Auth::login($user);
            return redirect()->intended('/dashboard');
        }
    }

    // Recovery code verification
    if ($request->filled('recovery_code')) {
        if (Sentinel::recoveryCodes()->verify($user, $request->input('recovery_code'))) {
            Sentinel::markMultiFactorComplete($request);
            Auth::login($user);

            // Warn user about remaining codes
            $remaining = Sentinel::recoveryCodes()->remaining($user);
            session()->flash('warning', "Recovery code used. You have {$remaining} codes remaining.");

            return redirect()->intended('/dashboard');
        }
    }

    return back()->withErrors(['code' => 'Invalid verification code.']);
}
```

## multi-factor Challenge Form

Provide toggle between TOTP and recovery code:

```blade
<form method="POST" action="{{ route('mfa.verify') }}">
    @csrf

    <div x-data="{ useRecoveryCode: false }">
        <div x-show="!useRecoveryCode">
            <label>
                Enter the 6-digit code from your authenticator app:
                <input type="text" name="code" pattern="[0-9]{6}" autofocus>
            </label>

            <button type="button" @click="useRecoveryCode = true" class="link">
                Use a recovery code instead
            </button>
        </div>

        <div x-show="useRecoveryCode" x-cloak>
            <label>
                Enter a recovery code:
                <input type="text" name="recovery_code" pattern="[A-Z0-9]{5}-[A-Z0-9]{5}">
            </label>

            <button type="button" @click="useRecoveryCode = false" class="link">
                Use authenticator app instead
            </button>
        </div>

        <button type="submit">Verify</button>
    </div>
</form>
```

## Regenerating Recovery Codes

Allow users to regenerate codes if lost:

```php
use Cline\Sentinel\Facades\Sentinel;

public function regenerateRecoveryCodes(Request $request)
{
    // Require password or sudo mode confirmation first
    if (!Hash::check($request->input('password'), $request->user()->password)) {
        return back()->withErrors(['password' => 'Invalid password.']);
    }

    $codes = Sentinel::recoveryCodes()->generate($request->user());

    return view('auth.recovery-codes', [
        'codes' => $codes,
        'regenerated' => true,
    ]);
}
```

## Checking Remaining Codes

Display remaining codes count to users:

```php
$remaining = Sentinel::recoveryCodes()->remaining($user);

if ($remaining === 0) {
    // Prompt user to regenerate
    session()->flash('warning', 'You have no recovery codes left. Generate new ones now.');
} elseif ($remaining <= 2) {
    // Warning for low codes
    session()->flash('info', "You only have {$remaining} recovery codes remaining.");
}
```

In your settings page:

```blade
<div class="security-section">
    <h3>Recovery Codes</h3>

    @if(Sentinel::for($user)->hasRecoveryCodes())
        <p>
            You have <strong>{{ Sentinel::recoveryCodes()->remaining($user) }}</strong>
            recovery codes remaining.
        </p>

        <form method="POST" action="{{ route('recovery-codes.regenerate') }}">
            @csrf
            <input type="password" name="password" placeholder="Confirm your password" required>
            <button type="submit">Regenerate Recovery Codes</button>
        </form>
    @else
        <p>You don't have any recovery codes yet.</p>
        <form method="POST" action="{{ route('recovery-codes.generate') }}">
            @csrf
            <button type="submit">Generate Recovery Codes</button>
        </form>
    @endif
</div>
```

## Invalidating Codes

Remove all recovery codes when disabling multi-factor:

```php
use Cline\Sentinel\Facades\Sentinel;

public function disableMfa(Request $request)
{
    // Disable all multi-factor methods
    Sentinel::disableAllMfa($request->user());

    // This automatically invalidates recovery codes too

    return redirect()->route('settings.security')
        ->with('status', 'Multi-factor authentication disabled.');
}
```

Or invalidate just recovery codes:

```php
Sentinel::recoveryCodes()->invalidate($request->user());
```

## Events

Recovery code operations dispatch events:

```php
use Cline\Sentinel\Events\RecoveryCodesGenerated;
use Cline\Sentinel\Events\RecoveryCodeUsed;

// Notify when codes are generated
Event::listen(RecoveryCodesGenerated::class, function ($event) {
    Mail::to($event->user)->send(new RecoveryCodesGeneratedMail($event->count));
});

// Alert when code is used (potential compromise)
Event::listen(RecoveryCodeUsed::class, function ($event) {
    $remaining = Sentinel::recoveryCodes()->remaining($event->user);

    Mail::to($event->user)->send(new RecoveryCodeUsedMail($remaining));

    // Log for security monitoring
    Log::info('Recovery code used', [
        'user_id' => $event->user->id,
        'remaining' => $remaining,
    ]);
});
```

## Security Best Practices

1. **Always hash codes** - Never store plain text codes in database
2. **Show codes only once** - Force user to save them immediately
3. **Require confirmation** - Ask for password before regenerating
4. **Send notifications** - Alert user when codes are generated or used
5. **Monitor usage** - Log when recovery codes are consumed
6. **Prompt regeneration** - Warn when codes are running low
7. **Disable with multi-factor** - Remove codes when multi-factor is disabled

## User Model Helpers

Check recovery code status:

```php
if (Sentinel::for($user)->hasRecoveryCodes()) {
    // User has recovery codes available
}

// Get recovery codes relationship
$codes = $user->mfaRecoveryCodes;

// Count unused codes
$unused = $user->mfaRecoveryCodes()->whereNull('used_at')->count();
```

## Troubleshooting

### Codes Not Working

- **Format**: Ensure uppercase and include dash (XXXXX-XXXXX)
- **Already used**: Each code works only once
- **Regenerated**: Old codes are invalidated when new ones are generated

### Codes Count Incorrect

```php
// Verify count in database
$count = MfaRecoveryCode::where('user_id', $user->id)
    ->whereNull('used_at')
    ->count();
```

### Security Concerns

If you suspect codes are compromised:

```php
// Immediately regenerate
$newCodes = Sentinel::recoveryCodes()->generate($user);

// Send notification
Mail::to($user)->send(new SecurityAlertMail());
```

## Complete Example

Full flow from multi-factor enablement to recovery code usage:

```php
// 1. Enable TOTP
public function confirmTotp(Request $request)
{
    $confirmed = Sentinel::totp()->confirmSetup(
        $request->user(),
        $request->input('code')
    );

    if (!$confirmed) {
        return back()->withErrors(['code' => 'Invalid code.']);
    }

    // 2. Generate recovery codes
    $codes = Sentinel::recoveryCodes()->generate($request->user());

    return view('auth.recovery-codes', ['codes' => $codes]);
}

// 3. User saves codes and continues
public function acknowledgeRecoveryCodes(Request $request)
{
    return redirect()->route('dashboard')
        ->with('status', 'Two-factor authentication enabled successfully!');
}

// 4. Later, user loses device and uses recovery code
public function verifyMfa(Request $request)
{
    $user = Sentinel::getChallengedUser($request);

    if ($request->filled('recovery_code')) {
        if (Sentinel::recoveryCodes()->verify($user, $request->input('recovery_code'))) {
            Sentinel::markMultiFactorComplete($request);
            Auth::login($user);

            $remaining = Sentinel::recoveryCodes()->remaining($user);

            return redirect()->route('settings.security')
                ->with('warning', "Recovery code used. {$remaining} codes remaining. Consider regenerating.");
        }
    }

    return back()->withErrors(['recovery_code' => 'Invalid recovery code.']);
}
```

<a id="doc-docs-security-keys"></a>

Security keys are device-bound WebAuthn credentials stored on physical hardware authenticators like YubiKey, Titan Key, or built-in platform authenticators. Unlike passkeys which sync across devices, security keys remain bound to a single physical device, making them ideal for high-security environments and compliance requirements.

## Overview

Security keys provide:
- **Device-bound credentials**: Never leave the physical device
- **Strong phishing protection**: Origin verification prevents phishing attacks
- **Hardware-backed security**: Private keys stored in secure hardware
- **Zero-knowledge proof**: Server never sees the private key
- **Compliance ready**: Meets FIDO2, NIST, and SOC2 requirements

**Key Differences from Passkeys:**

| Feature | Security Keys | Passkeys |
|---------|--------------|----------|
| Storage | Single device (hardware) | Synced across devices (cloud) |
| Portability | Require physical device | Available on all user's devices |
| Recovery | Backup keys recommended | Automatic via cloud sync |
| Use Case | High-security, compliance | Consumer convenience |
| `asPasskey` parameter | `false` | `true` |
| Credential type | `'webauthn'` | `'passkey'` |

## Requirements

### Browser Support

Security keys work in all modern browsers:
- Chrome/Edge 67+ (full support)
- Firefox 60+ (full support)
- Safari 13+ (full support)

### HTTPS Requirement

WebAuthn requires HTTPS in production. Localhost works for development:
- ✅ `https://example.com`
- ✅ `http://localhost`
- ✅ `http://127.0.0.1`
- ❌ `http://example.com` (production)

### Hardware Requirements

Supported authenticators:
- **USB Security Keys**: YubiKey 5 Series, Titan Security Key, Feitian ePass
- **NFC Security Keys**: YubiKey 5 NFC, Google Titan Key (NFC)
- **Platform Authenticators**: Windows Hello, Touch ID, Face ID (when used without syncing)

## Configuration

Update your `.env` file:

```bash
# WebAuthn Configuration
SENTINEL_RP_ID=example.com              # Your domain (no protocol, no port)
SENTINEL_RP_NAME="Your Application"     # Displayed to users during registration
```

**Important RP ID Rules:**
- Must match your application's domain
- No protocol (`https://`), no port (`:443`)
- For `https://app.example.com` → use `app.example.com` or `example.com`
- For localhost development → use `localhost`

The configuration in `config/sentinel.php` enables security keys:

```php
'methods' => [
    'webauthn' => [
        'enabled' => true,
        'relying_party' => [
            'id' => env('SENTINEL_RP_ID'),
            'name' => env('SENTINEL_RP_NAME', env('APP_NAME', 'Laravel')),
        ],
    ],
],
```

## Registration Flow

### Controller Implementation

Create a controller for security key registration:

```php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Cline\Sentinel\Facades\Sentinel;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class SecurityKeyRegistrationController extends Controller
{
    /**
     * Generate registration options for a new security key.
     */
    public function options(Request $request): JsonResponse
    {
        // Generate WebAuthn registration options
        $options = Sentinel::webAuthn()->beginRegistration(
            user: $request->user(),
            asPasskey: false, // Device-bound credential
        );

        // Store options in session for verification
        session([
            config('sentinel.session.webauthn_registration_options') => $options,
        ]);

        return response()->json([
            'options' => json_decode($options, true),
        ]);
    }

    /**
     * Verify and store the security key credential.
     */
    public function verify(Request $request): JsonResponse
    {
        $request->validate([
            'credential' => ['required', 'string'],
            'name' => ['required', 'string', 'max:255'],
        ]);

        try {
            $credential = Sentinel::webAuthn()->confirmRegistration(
                user: $request->user(),
                credentialJson: $request->input('credential'),
                optionsJson: session(config('sentinel.session.webauthn_registration_options')),
                hostname: $request->getHost(),
                name: $request->input('name'),
                type: 'webauthn', // Security key type
            );

            // Clear session data
            session()->forget(config('sentinel.session.webauthn_registration_options'));

            return response()->json([
                'message' => 'Security key registered successfully.',
                'credential' => [
                    'id' => $credential->id,
                    'name' => $credential->name,
                    'created_at' => $credential->created_at->toIso8601String(),
                ],
            ]);
        } catch (\Cline\Sentinel\Exceptions\InvalidWebAuthnAssertionException $exception) {
            return response()->json([
                'message' => 'Security key verification failed.',
                'error' => $exception->getMessage(),
            ], 422);
        }
    }

    /**
     * Remove a security key.
     */
    public function destroy(Request $request, string $credentialId): JsonResponse
    {
        Sentinel::webAuthn()->remove(
            user: $request->user(),
            credentialId: $credentialId,
        );

        return response()->json([
            'message' => 'Security key removed successfully.',
        ]);
    }
}
```

### Routes

Add routes in `routes/web.php`:

```php
use App\Http\Controllers\Auth\SecurityKeyRegistrationController;

Route::middleware(['auth'])->group(function () {
    // Security key registration
    Route::post('/auth/security-keys/options', [SecurityKeyRegistrationController::class, 'options'])
        ->name('auth.security-keys.options');

    Route::post('/auth/security-keys/verify', [SecurityKeyRegistrationController::class, 'verify'])
        ->name('auth.security-keys.verify');

    Route::delete('/auth/security-keys/{credential}', [SecurityKeyRegistrationController::class, 'destroy'])
        ->name('auth.security-keys.destroy');
});
```

## Authentication Flow (Multi-Factor Challenge)

### Controller Implementation

Create a controller for security key authentication:

```php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Cline\Sentinel\Facades\Sentinel;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class SecurityKeyAuthenticationController extends Controller
{
    /**
     * Generate authentication options for multi-factor challenge.
     */
    public function options(Request $request): JsonResponse
    {
        // Ensure user is in multi-factor challenge state
        $userId = session(config('sentinel.session.multi_factor_challenge_user_id'));

        if (!$userId) {
            return response()->json([
                'message' => 'No active multi-factor challenge.',
            ], 403);
        }

        $user = \App\Models\User::findOrFail($userId);

        // Generate authentication options
        $options = Sentinel::webAuthn()->beginAuthentication($user);

        // Store options in session for verification
        session([
            config('sentinel.session.webauthn_authentication_options') => $options,
        ]);

        return response()->json([
            'options' => json_decode($options, true),
        ]);
    }

    /**
     * Verify security key assertion and complete multi-factor.
     */
    public function verify(Request $request): JsonResponse
    {
        $request->validate([
            'credential' => ['required', 'string'],
        ]);

        try {
            $credential = Sentinel::webAuthn()->verify(
                credentialJson: $request->input('credential'),
                optionsJson: session(config('sentinel.session.webauthn_authentication_options')),
                hostname: $request->getHost(),
            );

            // Mark multi-factor as completed
            session([
                config('sentinel.session.multi_factor_completed_at') => now()->timestamp,
            ]);

            // Clear challenge state
            session()->forget([
                config('sentinel.session.multi_factor_challenge_user_id'),
                config('sentinel.session.webauthn_authentication_options'),
            ]);

            return response()->json([
                'message' => 'multi-factor verification successful.',
                'redirect' => route('dashboard'),
            ]);
        } catch (\Cline\Sentinel\Exceptions\InvalidWebAuthnAssertionException $exception) {
            return response()->json([
                'message' => 'Security key verification failed.',
                'error' => $exception->getMessage(),
            ], 422);
        }
    }
}
```

### Routes

Add multi-factor routes:

```php
use App\Http\Controllers\Auth\SecurityKeyAuthenticationController;

Route::middleware(['guest'])->group(function () {
    // Security key multi-factor challenge
    Route::post('/auth/multi-factor/security-key/options', [SecurityKeyAuthenticationController::class, 'options'])
        ->name('auth.multi-factor.security-key.options');

    Route::post('/auth/multi-factor/security-key/verify', [SecurityKeyAuthenticationController::class, 'verify'])
        ->name('auth.multi-factor.security-key.verify');
});
```

## Frontend Implementation

### Livewire Component

Create a Livewire component for managing security keys:

```php
<?php

namespace App\Livewire\Auth;

use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Illuminate\Support\Collection;
use Livewire\Component;

class ManageSecurityKeys extends Component
{
    public Collection $credentials;

    public function mount(): void
    {
        $this->loadCredentials();
    }

    public function loadCredentials(): void
    {
        $this->credentials = MultiFactorCredential::query()
            ->where('user_id', auth()->id())
            ->where('type', 'webauthn')
            ->orderBy('created_at', 'desc')
            ->get();
    }

    public function removeCredential(string $credentialId): void
    {
        MultiFactorCredential::query()
            ->where('id', $credentialId)
            ->where('user_id', auth()->id())
            ->where('type', 'webauthn')
            ->delete();

        $this->loadCredentials();

        session()->flash('message', 'Security key removed successfully.');
    }

    public function render()
    {
        return view('livewire.auth.manage-security-keys');
    }
}
```

### Blade Template

Create `resources/views/livewire/auth/manage-security-keys.blade.php`:

```blade
<div x-data="securityKeyManager()" x-init="init()">
    <!-- Registration Section -->
    <div class="mb-8">
        <h2 class="text-2xl font-bold mb-4">Security Keys</h2>
        <p class="text-gray-600 mb-4">
            Add hardware security keys like YubiKey or Titan Key for strong two-factor authentication.
            Security keys remain on your physical device and never sync to the cloud.
        </p>

        <div x-show="!browserSupported" class="bg-yellow-50 border border-yellow-200 text-yellow-800 px-4 py-3 rounded mb-4">
            <p class="font-semibold">Browser Not Supported</p>
            <p class="text-sm">Your browser doesn't support WebAuthn. Please use Chrome, Firefox, Safari, or Edge.</p>
        </div>

        <div class="flex gap-4">
            <input
                type="text"
                x-model="keyName"
                placeholder="Security Key Name (e.g., YubiKey 5C)"
                class="flex-1 rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200"
            />
            <button
                @click="registerKey()"
                :disabled="registering || !browserSupported"
                class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
                x-text="registering ? 'Registering...' : 'Add Security Key'"
            ></button>
        </div>

        <div x-show="error" class="mt-4 bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded">
            <p x-text="error"></p>
        </div>

        <div x-show="success" class="mt-4 bg-green-50 border border-green-200 text-green-800 px-4 py-3 rounded">
            <p x-text="success"></p>
        </div>
    </div>

    <!-- Registered Keys List -->
    <div>
        <h3 class="text-xl font-semibold mb-4">Your Security Keys</h3>

        @if($credentials->isEmpty())
            <p class="text-gray-500">No security keys registered.</p>
        @else
            <div class="space-y-2">
                @foreach($credentials as $credential)
                    <div class="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                        <div>
                            <p class="font-medium">{{ $credential->name }}</p>
                            <p class="text-sm text-gray-500">
                                Added {{ $credential->created_at->diffForHumans() }}
                                @if($credential->last_used_at)
                                    • Last used {{ $credential->last_used_at->diffForHumans() }}
                                @endif
                            </p>
                        </div>
                        <button
                            wire:click="removeCredential('{{ $credential->id }}')"
                            wire:confirm="Are you sure you want to remove this security key?"
                            class="px-3 py-1 text-sm text-red-600 hover:text-red-800"
                        >
                            Remove
                        </button>
                    </div>
                @endforeach
            </div>
        @endif
    </div>
</div>

<script>
function securityKeyManager() {
    return {
        keyName: '',
        registering: false,
        error: null,
        success: null,
        browserSupported: false,

        init() {
            this.browserSupported = this.checkBrowserSupport();
        },

        checkBrowserSupport() {
            return window.PublicKeyCredential !== undefined
                && navigator.credentials !== undefined
                && typeof navigator.credentials.create === 'function';
        },

        async registerKey() {
            if (!this.keyName.trim()) {
                this.error = 'Please enter a name for your security key.';
                return;
            }

            this.registering = true;
            this.error = null;
            this.success = null;

            try {
                // Step 1: Get registration options
                const optionsResponse = await fetch('{{ route("auth.security-keys.options") }}', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
                    },
                });

                if (!optionsResponse.ok) {
                    throw new Error('Failed to get registration options');
                }

                const { options } = await optionsResponse.json();

                // Step 2: Create credential with hardware key
                const publicKey = this.preparePublicKeyOptions(options);
                const credential = await navigator.credentials.create({ publicKey });

                // Step 3: Verify and store credential
                const verifyResponse = await fetch('{{ route("auth.security-keys.verify") }}', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
                    },
                    body: JSON.stringify({
                        credential: JSON.stringify(this.credentialToJSON(credential)),
                        name: this.keyName,
                    }),
                });

                const result = await verifyResponse.json();

                if (!verifyResponse.ok) {
                    throw new Error(result.error || 'Verification failed');
                }

                this.success = 'Security key registered successfully!';
                this.keyName = '';

                // Reload the component to show new key
                setTimeout(() => {
                    window.location.reload();
                }, 1500);

            } catch (err) {
                console.error('Security key registration error:', err);
                this.error = err.message || 'Failed to register security key. Please try again.';
            } finally {
                this.registering = false;
            }
        },

        preparePublicKeyOptions(options) {
            return {
                ...options,
                challenge: this.base64ToArrayBuffer(options.challenge),
                user: {
                    ...options.user,
                    id: this.base64ToArrayBuffer(options.user.id),
                },
                excludeCredentials: options.excludeCredentials?.map(cred => ({
                    ...cred,
                    id: this.base64ToArrayBuffer(cred.id),
                })) || [],
            };
        },

        credentialToJSON(credential) {
            return {
                id: credential.id,
                rawId: this.arrayBufferToBase64(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: this.arrayBufferToBase64(credential.response.clientDataJSON),
                    attestationObject: this.arrayBufferToBase64(credential.response.attestationObject),
                },
            };
        },

        base64ToArrayBuffer(base64) {
            const binary = window.atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        },

        arrayBufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return window.btoa(binary)
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
        },
    };
}
</script>
```

### multi-factor Challenge Page

Create `resources/views/auth/multi-factor-challenge.blade.php`:

```blade
<div x-data="securityKeyChallenge()" x-init="init()">
    <h2 class="text-2xl font-bold mb-4">Security Key Verification</h2>
    <p class="text-gray-600 mb-6">Insert your security key and follow the prompts to complete authentication.</p>

    <div x-show="!browserSupported" class="bg-yellow-50 border border-yellow-200 text-yellow-800 px-4 py-3 rounded mb-4">
        <p>Your browser doesn't support WebAuthn. Please use a modern browser.</p>
    </div>

    <button
        @click="authenticate()"
        :disabled="authenticating || !browserSupported"
        class="w-full px-4 py-3 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
        x-text="authenticating ? 'Verifying Security Key...' : 'Verify with Security Key'"
    ></button>

    <div x-show="error" class="mt-4 bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded">
        <p x-text="error"></p>
    </div>
</div>

<script>
function securityKeyChallenge() {
    return {
        authenticating: false,
        error: null,
        browserSupported: false,

        init() {
            this.browserSupported = window.PublicKeyCredential !== undefined;
        },

        async authenticate() {
            this.authenticating = true;
            this.error = null;

            try {
                // Step 1: Get authentication options
                const optionsResponse = await fetch('{{ route("auth.multi-factor.security-key.options") }}', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
                    },
                });

                if (!optionsResponse.ok) {
                    throw new Error('Failed to get authentication options');
                }

                const { options } = await optionsResponse.json();

                // Step 2: Get assertion from security key
                const publicKey = this.preparePublicKeyOptions(options);
                const assertion = await navigator.credentials.get({ publicKey });

                // Step 3: Verify assertion
                const verifyResponse = await fetch('{{ route("auth.multi-factor.security-key.verify") }}', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
                    },
                    body: JSON.stringify({
                        credential: JSON.stringify(this.assertionToJSON(assertion)),
                    }),
                });

                const result = await verifyResponse.json();

                if (!verifyResponse.ok) {
                    throw new Error(result.error || 'Verification failed');
                }

                // Redirect to dashboard
                window.location.href = result.redirect;

            } catch (err) {
                console.error('Security key authentication error:', err);
                this.error = err.message || 'Authentication failed. Please try again.';
            } finally {
                this.authenticating = false;
            }
        },

        preparePublicKeyOptions(options) {
            return {
                ...options,
                challenge: this.base64ToArrayBuffer(options.challenge),
                allowCredentials: options.allowCredentials?.map(cred => ({
                    ...cred,
                    id: this.base64ToArrayBuffer(cred.id),
                })) || [],
            };
        },

        assertionToJSON(assertion) {
            return {
                id: assertion.id,
                rawId: this.arrayBufferToBase64(assertion.rawId),
                type: assertion.type,
                response: {
                    clientDataJSON: this.arrayBufferToBase64(assertion.response.clientDataJSON),
                    authenticatorData: this.arrayBufferToBase64(assertion.response.authenticatorData),
                    signature: this.arrayBufferToBase64(assertion.response.signature),
                    userHandle: assertion.response.userHandle
                        ? this.arrayBufferToBase64(assertion.response.userHandle)
                        : null,
                },
            };
        },

        base64ToArrayBuffer(base64) {
            const binary = window.atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        },

        arrayBufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return window.btoa(binary)
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
        },
    };
}
</script>
```

## Testing

### Feature Tests

Create tests for security key registration:

```php
<?php

use App\Models\User;
use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\Facades\Sentinel;

test('user can register a security key', function () {
    $user = User::factory()->create();

    // Get registration options
    $response = $this->actingAs($user)->postJson(route('auth.security-keys.options'));

    $response->assertOk();
    $response->assertJsonStructure(['options']);

    // Mock credential verification
    $credentialJson = '{"id":"test","rawId":"dGVzdA==","type":"public-key","response":{"clientDataJSON":"...","attestationObject":"..."}}';

    Sentinel::shouldReceive('webAuthn->confirmRegistration')
        ->once()
        ->andReturn(MultiFactorCredential::factory()->create([
            'user_id' => $user->id,
            'type' => 'webauthn',
            'name' => 'YubiKey 5C',
        ]));

    $response = $this->actingAs($user)->postJson(route('auth.security-keys.verify'), [
        'credential' => $credentialJson,
        'name' => 'YubiKey 5C',
    ]);

    $response->assertOk();
    $response->assertJson(['message' => 'Security key registered successfully.']);
});

test('user can authenticate with security key during multi-factor challenge', function () {
    $user = User::factory()->create();
    $credential = MultiFactorCredential::factory()->create([
        'user_id' => $user->id,
        'type' => 'webauthn',
    ]);

    // Set multi-factor challenge state
    session([config('sentinel.session.multi_factor_challenge_user_id') => $user->id]);

    // Get authentication options
    $response = $this->postJson(route('auth.multi-factor.security-key.options'));
    $response->assertOk();

    // Mock assertion verification
    $assertionJson = '{"id":"test","rawId":"dGVzdA==","type":"public-key","response":{"clientDataJSON":"...","authenticatorData":"...","signature":"..."}}';

    Sentinel::shouldReceive('webAuthn->verify')
        ->once()
        ->andReturn($credential);

    $response = $this->postJson(route('auth.multi-factor.security-key.verify'), [
        'credential' => $assertionJson,
    ]);

    $response->assertOk();
    $response->assertJson(['message' => 'multi-factor verification successful.']);

    // Verify multi-factor completed
    expect(session(config('sentinel.session.multi_factor_completed_at')))->not->toBeNull();
});

test('user can remove a security key', function () {
    $user = User::factory()->create();
    $credential = MultiFactorCredential::factory()->create([
        'user_id' => $user->id,
        'type' => 'webauthn',
    ]);

    $response = $this->actingAs($user)->deleteJson(
        route('auth.security-keys.destroy', $credential->id)
    );

    $response->assertOk();
    $this->assertDatabaseMissing('multi_factor_credentials', [
        'id' => $credential->id,
    ]);
});
```

## Troubleshooting

### "NotSupportedError: The operation is not supported"

**Cause**: Browser doesn't support WebAuthn or user doesn't have compatible hardware.

**Solutions**:
- Ensure HTTPS is enabled (or using localhost for development)
- Check browser compatibility (Chrome 67+, Firefox 60+, Safari 13+)
- Verify user has compatible hardware authenticator
- Check browser console for detailed error messages

### "NotAllowedError: The operation was cancelled"

**Cause**: User cancelled the operation or timeout occurred.

**Solutions**:
- User must interact with security key within timeout period (60 seconds)
- Ensure security key is properly inserted (USB) or within range (NFC/Bluetooth)
- Check if user has multiple security keys registered - only one should respond
- Verify user touches/activates the security key when prompted

### "SecurityError: The operation is insecure"

**Cause**: RP ID mismatch or insecure context.

**Solutions**:
- Ensure `SENTINEL_RP_ID` matches your domain exactly
- For `https://app.example.com` → use `app.example.com` or `example.com`
- For development → use `localhost` (not `127.0.0.1`)
- Verify HTTPS is enabled in production

### Credentials not found during authentication

**Cause**: No matching credentials or wrong RP ID.

**Solutions**:
- Verify user has security keys registered with `type = 'webauthn'`
- Check RP ID hasn't changed since registration
- Ensure same browser/device used for registration and authentication
- Verify credentials aren't excluded in authentication options

### Security key works on one domain but not another

**Cause**: WebAuthn credentials are scoped to RP ID.

**Solutions**:
- Credentials registered on `example.com` won't work on `app.example.com` unless RP ID is `example.com`
- Use parent domain as RP ID to share credentials across subdomains
- Re-register security keys if changing RP ID

### "InvalidStateError: The authenticator is already registered"

**Cause**: Trying to register the same security key twice.

**Solutions**:
- Implement `excludeCredentials` in registration options to prevent duplicates
- Check if credential already exists before registration
- User should use a different security key or remove existing one first

## Best Practices

### 1. Security Key Backup

Unlike passkeys, security keys don't sync. Recommend users:
- Register multiple security keys (primary + backup)
- Store backup key in secure location
- Enable recovery codes as fallback

```php
// Check if user has backup security keys
if (Sentinel::for($user)->getWebAuthnCredentials()->count() < 2) {
    // Show warning to register backup key
}
```

### 2. Device Detection

Help users understand which authenticator to use:

```javascript
// Detect available authenticator types
async function detectAuthenticators() {
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();

    return {
        platformAuthenticator: available, // Built-in (Touch ID, Windows Hello)
        externalAuthenticator: true,      // Always assume USB/NFC available
    };
}
```

### 3. User Guidance

Provide clear instructions:
- USB keys: "Insert your security key and touch it when prompted"
- NFC keys: "Hold your security key near your device"
- Platform authenticators: "Follow your device's authentication prompt"

### 4. Attestation Handling

For compliance, consider enabling attestation:

```php
// In GenerateRegistrationOptionsAction
$options = new PublicKeyCredentialCreationOptions(
    // ...
    attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
);
```

This provides cryptographic proof of authenticator model, useful for:
- Compliance requirements (NIST, FIDO2)
- Security auditing
- Restricting to specific hardware vendors

### 5. Counter Tracking

Monitor signature counters for cloning detection:

```php
// In VerifyAuthenticationAction, after verification
if ($newCounter <= $oldCounter && $oldCounter !== 0) {
    // Possible cloning attempt - invalidate credential
    Log::warning('Signature counter decreased', [
        'credential_id' => $credential->id,
        'old_counter' => $oldCounter,
        'new_counter' => $newCounter,
    ]);

    $credential->delete();
    throw new SecurityException('Security key may be compromised');
}
```

## Use Cases

### High-Security Environments

Security keys are ideal when:
- Credentials must never leave physical device
- Compliance requires hardware-backed authentication (NIST AAL3, FIDO2)
- Users work across shared/untrusted computers
- Organization manages physical security key distribution

### Multi-Factor Authentication

Combine security keys with other factors:
```php
// User must have security key OR TOTP enabled
if (!Sentinel::for($user)->hasWebAuthnEnabled() && !Sentinel::for($user)->hasTotpEnabled()) {
    // Require at least one multi-factor method
}
```

### Privileged Operations

Require security key for sensitive actions:
```php
Route::middleware(['auth', 'verified', 'security-key'])->group(function () {
    Route::post('/admin/users/{user}/disable', [AdminController::class, 'disableUser']);
    Route::delete('/billing/subscription', [BillingController::class, 'cancelSubscription']);
});
```

## Related Documentation

- [Passkeys Integration](#doc-docs-passkeys) - For synced credentials
- [Multi-Factor Authentication](#doc-docs-mfa) - Complete multi-factor guide
- [WebAuthn Events](#) - Event handling
- [Testing Guide](#) - Comprehensive testing

## External Resources

- [WebAuthn Guide](https://webauthn.guide/) - Interactive WebAuthn tutorial
- [FIDO Alliance](https://fidoalliance.org/) - FIDO2 specifications
- [web-auth/webauthn-framework](https://github.com/web-auth/webauthn-framework) - PHP library docs
- [YubiKey Documentation](https://www.yubico.com/resources/) - Hardware key specifics

<a id="doc-docs-sudo-mode"></a>

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

<a id="doc-docs-totp"></a>

TOTP (Time-based One-Time Password) provides multi-factor authentication using authenticator apps like Google Authenticator, Authy, Microsoft Authenticator, or 1Password.

## How TOTP Works

1. **Setup**: Server generates a secret key and shows QR code to user
2. **Registration**: User scans QR code with authenticator app
3. **Verification**: User enters 6-digit code from app to confirm setup
4. **Authentication**: During login, user provides code from app as second factor

## Configuration

Configure TOTP settings in `config/sentinel.php`:

```php
'methods' => [
    'totp' => [
        'enabled' => true,
        'issuer' => env('APP_NAME', 'Laravel'),  // Shown in authenticator apps
        'digits' => 6,        // Code length (6 or 8)
        'period' => 30,       // Seconds per code (30 is standard)
        'algorithm' => 'sha1', // sha1, sha256, or sha512
        'window' => 1,        // Allow codes 1 period before/after (clock drift)
    ],
],
```

### Configuration Options

- **issuer**: Name shown in authenticator apps (usually your app name)
- **digits**: Length of generated codes (6 is standard, 8 for higher security)
- **period**: How long each code is valid in seconds (30 is standard)
- **algorithm**: Hashing algorithm (sha1 is most compatible)
- **window**: Tolerance for clock drift (1 = accept previous/next code too)

## TOTP Setup Flow

### Step 1: Begin Setup

Generate a secret and show QR code to the user:

```php
use Cline\Sentinel\Facades\Sentinel;

public function setupTotp(Request $request)
{
    $setup = Sentinel::totp()->beginSetup($request->user());

    return view('auth.totp-setup', [
        'secret' => $setup->getSecret(),
        'qrCode' => $setup->getQrCodeSvg(),
        'provisioningUri' => $setup->getProvisioningUri(),
    ]);
}
```

### Display QR Code in Blade

```blade
<div class="totp-setup">
    <h2>Set Up Two-Factor Authentication</h2>

    <p>Scan this QR code with your authenticator app:</p>

    <div class="qr-code">
        {!! $qrCode !!}
    </div>

    <p>Or manually enter this code:</p>
    <code>{{ $secret }}</code>

    <form method="POST" action="{{ route('totp.confirm') }}">
        @csrf
        <label>
            Enter the 6-digit code from your app:
            <input type="text" name="code" pattern="[0-9]{6}" required autofocus>
        </label>
        <button type="submit">Verify &amp; Enable</button>
    </form>
</div>
```

### Step 2: Confirm Setup

Verify the code from the user's authenticator app:

```php
public function confirmTotp(Request $request)
{
    $request->validate([
        'code' => ['required', 'string', 'size:6'],
    ]);

    $confirmed = Sentinel::totp()->confirmSetup(
        $request->user(),
        $request->input('code')
    );

    if (!$confirmed) {
        return back()->withErrors([
            'code' => 'Invalid code. Please try again.'
        ]);
    }

    // TOTP enabled successfully - generate recovery codes
    $codes = Sentinel::recoveryCodes()->generate($request->user());

    return view('auth.recovery-codes', ['codes' => $codes]);
}
```

### Cancel Setup

Clear setup state if user navigates away:

```php
Sentinel::totp()->cancelSetup();
```

## TOTP Verification

### During Multi-Factor Challenge

```php
use Cline\Sentinel\Facades\Sentinel;

public function verifyMfa(Request $request)
{
    $user = Sentinel::getChallengedUser($request);

    $request->validate([
        'code' => ['required', 'string', 'size:6'],
    ]);

    $valid = Sentinel::totp()->verify(
        $user,
        $request->input('code')
    );

    if ($valid) {
        Sentinel::markMultiFactorComplete($request);
        Sentinel::clearMultiFactorChallenge($request);

        Auth::login($user);
        return redirect()->intended('/dashboard');
    }

    return back()->withErrors([
        'code' => 'Invalid verification code.'
    ]);
}
```

### Rate Limiting

Protect against brute force attacks:

```php
use Illuminate\Support\Facades\RateLimiter;

public function verifyMfa(Request $request)
{
    $key = 'multi-factor-verify:'.$request->ip();

    if (RateLimiter::tooManyAttempts($key, 5)) {
        $seconds = RateLimiter::availableIn($key);
        return back()->withErrors([
            'code' => "Too many attempts. Try again in {$seconds} seconds."
        ]);
    }

    $valid = Sentinel::totp()->verify($user, $request->input('code'));

    if (!$valid) {
        RateLimiter::hit($key, 300); // 5 minute lockout
        return back()->withErrors(['code' => 'Invalid code.']);
    }

    RateLimiter::clear($key);
    // ... complete authentication
}
```

## Disabling TOTP

Remove TOTP authentication for a user:

```php
use Cline\Sentinel\Facades\Sentinel;

public function disableTotp(Request $request)
{
    // Require password confirmation first
    if (!Hash::check($request->input('password'), $request->user()->password)) {
        return back()->withErrors(['password' => 'Invalid password.']);
    }

    Sentinel::totp()->disable($request->user());

    return redirect()->route('settings.security')
        ->with('status', 'Two-factor authentication disabled.');
}
```

## Checking TOTP Status

Check if a user has TOTP enabled:

```php
if (Sentinel::for($user)->hasTotpEnabled()) {
    // User has TOTP configured
}

// Or check any multi-factor method
if (Sentinel::for($user)->hasMultiFactorAuth()) {
    // User has at least one multi-factor method configured
}

// Get the credential
$credential = Sentinel::for($user)->getTotpCredential();
if ($credential) {
    echo "Last used: " . $credential->last_used_at;
}
```

## QR Code Methods

The `TotpSetup` object provides multiple ways to display QR codes:

```php
$setup = Sentinel::totp()->beginSetup($user);

// SVG string (for inline HTML)
$svg = $setup->getQrCodeSvg();

// Data URI (for img src)
$dataUri = $setup->getQrCodeDataUri();

// Provisioning URI (for manual entry)
$uri = $setup->getProvisioningUri();
// Returns: otpauth://totp/YourApp:user@example.com?secret=...

// Raw secret (for manual entry)
$secret = $setup->getSecret();
```

### Display Options

**Inline SVG** (best for styling):
```blade
<div class="qr-code">
    {!! $qrCode !!}
</div>
```

**Image tag**:
```blade
<img src="{{ $dataUri }}" alt="QR Code">
```

**Manual entry fallback**:
```blade
<p>Can't scan? Enter this code manually:</p>
<code>{{ $secret }}</code>
<p>Provisioning URI:</p>
<code>{{ $provisioningUri }}</code>
```

## Events

TOTP operations dispatch events:

```php
use Cline\Sentinel\Events\TotpEnabled;
use Cline\Sentinel\Events\TotpDisabled;
use Cline\Sentinel\Events\MfaChallengeFailed;

// Listen for TOTP enabled
Event::listen(TotpEnabled::class, function ($event) {
    // Send email notification
    Mail::to($event->user)->send(new TotpEnabledMail());
});

// Listen for failed attempts
Event::listen(MfaChallengeFailed::class, function ($event) {
    if ($event->method === 'totp') {
        // Log failed TOTP attempt
        Log::warning('Failed TOTP attempt', ['user_id' => $event->user->id]);
    }
});
```

## Best Practices

1. **Always generate recovery codes** after enabling TOTP
2. **Show recovery codes only once** - they can't be retrieved later
3. **Require password confirmation** before disabling TOTP
4. **Rate limit verification attempts** to prevent brute force
5. **Send email notifications** when TOTP is enabled/disabled
6. **Use window=1** to handle clock drift gracefully
7. **Test with multiple apps** (Google Authenticator, Authy, etc.)

## Troubleshooting

### Codes Always Invalid

- **Clock drift**: Increase `window` config to 2
- **Wrong algorithm**: Ensure app supports your algorithm (sha1 is safest)
- **Wrong secret**: User may have scanned old QR code - regenerate

### QR Code Won't Scan

- **Too small**: Increase size with CSS
- **Wrong format**: Some apps prefer data URI over inline SVG
- **Invalid URI**: Check `issuer` doesn't have special characters

### Provisioning URI Issues

Ensure issuer and account name are URL-encoded:
```php
// The package handles this automatically
$uri = $setup->getProvisioningUri();
```

<a id="doc-docs-webauthn"></a>

WebAuthn provides modern, phishing-resistant authentication using hardware security keys (YubiKey, Titan) or platform authenticators (Touch ID, Face ID, Windows Hello).

## What is WebAuthn?

WebAuthn is a web standard for passwordless authentication that uses public-key cryptography. Instead of codes, users authenticate with:

- **Security Keys**: Physical USB/NFC devices (YubiKey, Titan Key)
- **Platform Authenticators**: Built-in biometrics (Touch ID, Face ID, Windows Hello)
- **Passkeys**: Synced credentials across devices (iCloud Keychain, Google Password Manager)

## Benefits

- **Phishing-resistant**: Cryptographic verification prevents credential theft
- **No shared secrets**: Private keys never leave the device
- **User-friendly**: Tap a key or use biometrics instead of typing codes
- **Multi-device**: Passkeys sync across user's devices automatically

## Configuration

Configure WebAuthn in `config/sentinel.php`:

```php
'methods' => [
    'webauthn' => [
        'enabled' => true,
        'relying_party' => [
            'name' => env('APP_NAME', 'Laravel'),
            'id' => env('WEBAUTHN_ID', parse_url(env('APP_URL'), PHP_URL_HOST)),
        ],
        'timeout' => 60000, // milliseconds (60 seconds)
        'attestation' => 'none', // 'none', 'indirect', or 'direct'
        'user_verification' => 'preferred', // 'required', 'preferred', or 'discouraged'
    ],
],
```

### Configuration Options

- **relying_party.name**: Your application name (shown during registration)
- **relying_party.id**: Your domain (must match current hostname)
- **timeout**: How long user has to complete registration/authentication
- **attestation**: Verification level for authenticator device
- **user_verification**: Whether biometrics/PIN is required

## WebAuthn Registration Flow

### Step 1: Begin Registration

Generate registration options for the user:

```php
use Cline\Sentinel\Facades\Sentinel;

public function beginRegistration(Request $request)
{
    $options = Sentinel::webAuthn()->beginRegistration(
        $request->user(),
        $request->input('credential_name', 'Security Key')
    );

    // Store challenge in session for verification
    session(['webauthn_challenge' => $options['challenge']]);

    return response()->json($options);
}
```

### Step 2: Frontend Registration

Use JavaScript to register the credential:

```html
<div x-data="webauthnRegistration">
    <button @click="register">Add Security Key</button>
</div>

<script>
document.addEventListener('alpine:init', () => {
    Alpine.data('webauthnRegistration', () => ({
        async register() {
            try {
                // Get registration options from server
                const response = await fetch('/webauthn/register/options', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
                    },
                    body: JSON.stringify({
                        credential_name: 'My Security Key',
                    }),
                });

                const options = await response.json();

                // Convert base64 strings to ArrayBuffer
                options.challenge = this.base64ToArrayBuffer(options.challenge);
                options.user.id = this.base64ToArrayBuffer(options.user.id);

                // Prompt user to use their authenticator
                const credential = await navigator.credentials.create({
                    publicKey: options,
                });

                // Send credential to server
                const verifyResponse = await fetch('/webauthn/register/verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
                    },
                    body: JSON.stringify({
                        credential: {
                            id: credential.id,
                            rawId: this.arrayBufferToBase64(credential.rawId),
                            response: {
                                clientDataJSON: this.arrayBufferToBase64(credential.response.clientDataJSON),
                                attestationObject: this.arrayBufferToBase64(credential.response.attestationObject),
                            },
                            type: credential.type,
                        },
                    }),
                });

                if (verifyResponse.ok) {
                    alert('Security key registered successfully!');
                    window.location.reload();
                }
            } catch (error) {
                console.error('WebAuthn registration failed:', error);
                alert('Failed to register security key. Please try again.');
            }
        },

        base64ToArrayBuffer(base64) {
            const binary = window.atob(base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        },

        arrayBufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return window.btoa(binary);
        },
    }));
});
</script>
```

### Step 3: Verify Registration

Verify the credential on the server:

```php
use Cline\Sentinel\Facades\Sentinel;

public function verifyRegistration(Request $request)
{
    $request->validate([
        'credential' => ['required', 'array'],
    ]);

    $challenge = session('webauthn_challenge');

    if (!$challenge) {
        return response()->json(['error' => 'Invalid session'], 400);
    }

    try {
        $credential = Sentinel::webAuthn()->verifyRegistration(
            $request->user(),
            $request->input('credential'),
            $challenge
        );

        session()->forget('webauthn_challenge');

        return response()->json([
            'success' => true,
            'credential' => [
                'id' => $credential->id,
                'name' => $credential->name,
            ],
        ]);
    } catch (\Exception $e) {
        return response()->json(['error' => $e->getMessage()], 400);
    }
}
```

## WebAuthn Authentication Flow

### Step 1: Begin Authentication

Generate authentication options:

```php
use Cline\Sentinel\Facades\Sentinel;

public function beginAuthentication(Request $request)
{
    $user = Sentinel::getChallengedUser($request);

    $options = Sentinel::webAuthn()->beginAuthentication($user);

    session(['webauthn_auth_challenge' => $options['challenge']]);

    return response()->json($options);
}
```

### Step 2: Frontend Authentication

Prompt user to authenticate:

```html
<div x-data="webauthnAuthentication">
    <button @click="authenticate">Use Security Key</button>
</div>

<script>
document.addEventListener('alpine:init', () => {
    Alpine.data('webauthnAuthentication', () => ({
        async authenticate() {
            try {
                // Get authentication options
                const response = await fetch('/webauthn/authenticate/options', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
                    },
                });

                const options = await response.json();

                // Convert challenge
                options.challenge = this.base64ToArrayBuffer(options.challenge);

                // Convert credential IDs
                if (options.allowCredentials) {
                    options.allowCredentials = options.allowCredentials.map(cred => ({
                        ...cred,
                        id: this.base64ToArrayBuffer(cred.id),
                    }));
                }

                // Prompt user to authenticate
                const assertion = await navigator.credentials.get({
                    publicKey: options,
                });

                // Send assertion to server
                const verifyResponse = await fetch('/webauthn/authenticate/verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
                    },
                    body: JSON.stringify({
                        assertion: {
                            id: assertion.id,
                            rawId: this.arrayBufferToBase64(assertion.rawId),
                            response: {
                                clientDataJSON: this.arrayBufferToBase64(assertion.response.clientDataJSON),
                                authenticatorData: this.arrayBufferToBase64(assertion.response.authenticatorData),
                                signature: this.arrayBufferToBase64(assertion.response.signature),
                                userHandle: assertion.response.userHandle
                                    ? this.arrayBufferToBase64(assertion.response.userHandle)
                                    : null,
                            },
                            type: assertion.type,
                        },
                    }),
                });

                if (verifyResponse.ok) {
                    window.location.href = '/dashboard';
                }
            } catch (error) {
                console.error('WebAuthn authentication failed:', error);
                alert('Authentication failed. Please try again.');
            }
        },

        base64ToArrayBuffer(base64) {
            const binary = window.atob(base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        },

        arrayBufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return window.btoa(binary);
        },
    }));
});
</script>
```

### Step 3: Verify Authentication

Verify the assertion on the server:

```php
use Cline\Sentinel\Facades\Sentinel;

public function verifyAuthentication(Request $request)
{
    $request->validate([
        'assertion' => ['required', 'array'],
    ]);

    $user = Sentinel::getChallengedUser($request);
    $challenge = session('webauthn_auth_challenge');

    if (!$challenge) {
        return response()->json(['error' => 'Invalid session'], 400);
    }

    try {
        $verified = Sentinel::webAuthn()->verifyAuthentication(
            $user,
            $request->input('assertion'),
            $challenge
        );

        if ($verified) {
            session()->forget('webauthn_auth_challenge');
            Sentinel::markMfaComplete($request);
            Auth::login($user);

            return response()->json(['success' => true]);
        }

        return response()->json(['error' => 'Verification failed'], 400);
    } catch (\Exception $e) {
        return response()->json(['error' => $e->getMessage()], 400);
    }
}
```

## Managing Credentials

### List User Credentials

```php
public function listCredentials(Request $request)
{
    $credentials = $request->user()->webAuthnCredentials;

    return view('settings.webauthn', [
        'credentials' => $credentials,
    ]);
}
```

Display in Blade:

```blade
<div class="webauthn-credentials">
    <h3>Security Keys</h3>

    @forelse($credentials as $credential)
        <div class="credential-item">
            <div>
                <strong>{{ $credential->name }}</strong>
                <small>Added {{ $credential->created_at->diffForHumans() }}</small>
                @if($credential->last_used_at)
                    <small>Last used {{ $credential->last_used_at->diffForHumans() }}</small>
                @endif
            </div>

            <form method="POST" action="{{ route('webauthn.remove', $credential) }}">
                @csrf
                @method('DELETE')
                <button type="submit">Remove</button>
            </form>
        </div>
    @empty
        <p>No security keys registered.</p>
    @endforelse

    <button onclick="registerWebAuthn()">Add Security Key</button>
</div>
```

### Remove Credential

```php
use Cline\Sentinel\Facades\Sentinel;

public function removeCredential(Request $request, MfaCredential $credential)
{
    // Verify ownership
    if ($credential->user_id !== $request->user()->id) {
        abort(403);
    }

    Sentinel::webAuthn()->removeCredential($credential);

    return back()->with('status', 'Security key removed.');
}
```

## Browser Support

Check browser support before showing WebAuthn options:

```javascript
if (window.PublicKeyCredential) {
    // WebAuthn is supported
    document.getElementById('webauthn-option').style.display = 'block';
} else {
    // WebAuthn not supported
    console.log('WebAuthn not supported in this browser');
}
```

## Passkeys vs Security Keys

**Passkeys** (synced credentials):
- Stored in iCloud Keychain, Google Password Manager, etc.
- Sync across user's devices automatically
- More convenient for users
- Requires platform support (iOS 16+, Android 9+, etc.)

**Security Keys** (device-bound):
- Physical USB/NFC devices
- Never leave the device
- More secure but less convenient
- Works on any platform with USB/NFC

Both use the same WebAuthn API—the user chooses during registration.

## User Model Helpers

```php
// Check if user has WebAuthn enabled
if (Sentinel::for($user)->hasWebAuthnEnabled()) {
    // User has at least one WebAuthn credential
}

// Get all WebAuthn credentials
$credentials = Sentinel::for($user)->getWebAuthnCredentials();

// Count credentials
$count = Sentinel::for($user)->getWebAuthnCredentials()()->count();
```

## Events

WebAuthn operations dispatch events:

```php
use Cline\Sentinel\Events\WebAuthnCredentialRegistered;
use Cline\Sentinel\Events\WebAuthnCredentialRemoved;

Event::listen(WebAuthnCredentialRegistered::class, function ($event) {
    Mail::to($event->user)->send(new WebAuthnRegisteredMail($event->credential));
});

Event::listen(WebAuthnCredentialRemoved::class, function ($event) {
    Log::info('WebAuthn credential removed', [
        'user_id' => $event->user->id,
        'credential_id' => $event->credentialId,
    ]);
});
```

## Best Practices

1. **Require HTTPS** - WebAuthn only works over HTTPS
2. **Name credentials** - Let users name their keys/devices
3. **Show last used** - Display when each credential was last used
4. **Allow multiple** - Users should have multiple credentials as backup
5. **Combine with TOTP** - Offer both WebAuthn and TOTP for flexibility
6. **Test across browsers** - WebAuthn implementation varies by browser
7. **Provide fallback** - Always have recovery codes available

## Troubleshooting

### WebAuthn Not Working

**HTTPS Required:**
```
WebAuthn requires HTTPS (or localhost for development)
```

**Domain Mismatch:**
```
Relying Party ID must match current domain
```
Ensure `config/sentinel.php` relying_party.id matches your domain.

**Browser Compatibility:**
- Chrome 67+
- Firefox 60+
- Safari 13+
- Edge 18+

### User Verification Fails

If biometrics aren't working, adjust user verification:

```php
'user_verification' => 'discouraged', // Don't require biometrics
```

### Timeout Issues

Increase timeout for slower users:

```php
'timeout' => 120000, // 2 minutes
```

## Complete Example

Full WebAuthn setup with fallback to TOTP:

```blade
<div class="mfa-challenge">
    <h2>Verify Your Identity</h2>

    <div x-data="{ method: 'webauthn' }">
        <!-- WebAuthn Option -->
        <div x-show="method === 'webauthn'" id="webauthn-option">
            <p>Use your security key or biometrics:</p>
            <button @click="authenticateWithWebAuthn()">
                Use Security Key
            </button>
            <button type="button" @click="method = 'totp'">
                Use authenticator app instead
            </button>
        </div>

        <!-- TOTP Fallback -->
        <div x-show="method === 'totp'">
            <form method="POST" action="{{ route('mfa.verify') }}">
                @csrf
                <label>
                    Enter 6-digit code:
                    <input type="text" name="code" pattern="[0-9]{6}">
                </label>
                <button type="submit">Verify</button>
            </form>
            <button type="button" @click="method = 'webauthn'">
                Use security key instead
            </button>
        </div>
    </div>
</div>

<script>
async function authenticateWithWebAuthn() {
    // ... authentication code from examples above ...
}
</script>
```

## Resources

- [WebAuthn Guide](https://webauthn.guide/)
- [Web Authentication API Docs](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
- [FIDO Alliance](https://fidoalliance.org/)
- [Can I Use WebAuthn](https://caniuse.com/webauthn)
