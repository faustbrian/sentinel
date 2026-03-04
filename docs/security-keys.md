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

- [Passkeys Integration](./passkeys.md) - For synced credentials
- [Multi-Factor Authentication](./mfa.md) - Complete multi-factor guide
- [WebAuthn Events](./events#webauthn-events.md) - Event handling
- [Testing Guide](./testing#webauthn-tests.md) - Comprehensive testing

## External Resources

- [WebAuthn Guide](https://webauthn.guide/) - Interactive WebAuthn tutorial
- [FIDO Alliance](https://fidoalliance.org/) - FIDO2 specifications
- [web-auth/webauthn-framework](https://github.com/web-auth/webauthn-framework) - PHP library docs
- [YubiKey Documentation](https://www.yubico.com/resources/) - Hardware key specifics
