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
