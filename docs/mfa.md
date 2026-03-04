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

- [Passkeys Integration](./passkeys.md) - Synced WebAuthn credentials
- [Security Keys Integration](./security-keys.md) - Device-bound credentials
- [TOTP Setup](./totp.md) - Authenticator app configuration
- [Events](./events.md) - multi-factor event handling
- [Testing](./testing.md) - Comprehensive test examples

## External Resources

- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/) - multi-factor standards
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [WebAuthn Guide](https://webauthn.guide/) - Interactive tutorial
- [Google Authenticator](https://support.google.com/accounts/answer/1066447) - TOTP setup
