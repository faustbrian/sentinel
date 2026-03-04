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

- [TOTP Configuration](totp.md) - Set up authenticator app authentication
- [Recovery Codes](recovery-codes.md) - Emergency backup access
- [WebAuthn/Passkeys](webauthn.md) - Security key and biometric authentication
- [Sudo Mode](sudo-mode.md) - Re-verify identity for critical actions
- [Middleware](middleware.md) - Protect routes with multi-factor requirements
- [Events](events.md) - Listen to multi-factor lifecycle events
