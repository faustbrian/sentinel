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
