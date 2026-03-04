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
