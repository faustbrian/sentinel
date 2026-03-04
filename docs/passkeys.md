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

- [Security Keys](./security-keys.md) - Device-bound WebAuthn credentials
- [Recovery Codes](./recovery-codes.md) - Backup authentication method
- [Events](./events.md) - Listen to passkey registration/usage
