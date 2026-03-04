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
