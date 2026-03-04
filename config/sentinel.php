<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

return [
    /*
    |--------------------------------------------------------------------------
    | TOTP (Time-based One-Time Password)
    |--------------------------------------------------------------------------
    |
    | Configure TOTP authenticator app settings.
    |
    */
    'totp' => [
        'enabled' => true,
        'issuer' => env('APP_NAME', 'Laravel'),
        'digits' => 6,
        'period' => 30,
        'algorithm' => 'sha1',
        'window' => 1,
    ],

    /*
    |--------------------------------------------------------------------------
    | WebAuthn (Security Keys & Biometrics)
    |--------------------------------------------------------------------------
    |
    | Configure WebAuthn/FIDO2 authentication settings.
    |
    */
    'webauthn' => [
        'enabled' => true,
        'relying_party' => [
            'id' => env('SENTINEL_RP_ID'),
            'name' => env('SENTINEL_RP_NAME', env('APP_NAME', 'Laravel')),
        ],
        'timeout' => 60000,
        'attestation' => 'none',
        'authenticator_attachment' => null,
        'user_verification' => 'preferred',
    ],

    /*
    |--------------------------------------------------------------------------
    | Passkeys
    |--------------------------------------------------------------------------
    |
    | Configure passkey authentication settings.
    |
    */
    'passkey' => [
        'enabled' => true,
        'relying_party' => [
            'id' => env('SENTINEL_RP_ID'),
            'name' => env('SENTINEL_RP_NAME', env('APP_NAME', 'Laravel')),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Recovery Codes
    |--------------------------------------------------------------------------
    |
    | Configure recovery code settings for backup access.
    |
    */
    'recovery_codes' => [
        'enabled' => true,
        'count' => 8,
        'length' => 10,
        'format' => 'XXXXX-XXXXX',
    ],

    /*
    |--------------------------------------------------------------------------
    | Sudo Mode
    |--------------------------------------------------------------------------
    |
    | Sudo mode requires users to re-authenticate for sensitive operations.
    | The duration specifies how long (in seconds) sudo mode remains active
    | after confirmation before requiring re-authentication.
    |
    */
    'sudo_mode' => [
        'enabled' => true,
        'duration' => 900,
    ],

    /*
    |--------------------------------------------------------------------------
    | Session Keys
    |--------------------------------------------------------------------------
    |
    | Session key names used to track MFA challenge state, completion status,
    | sudo mode confirmation, and temporary setup secrets. Customize these if
    | they conflict with your application's session keys.
    |
    */
    'session' => [
        'multi_factor_challenge_user_id' => 'sentinel.multi_factor_challenge_user_id',
        'multi_factor_completed_at' => 'sentinel.multi_factor_completed_at',
        'sudo_confirmed_at' => 'sentinel.sudo_confirmed_at',
        'totp_setup_secret' => 'sentinel.totp_setup_secret',
        'webauthn_registration_options' => 'sentinel.webauthn_registration_options',
        'webauthn_authentication_options' => 'sentinel.webauthn_authentication_options',
    ],

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    |
    | Default route paths for MFA challenge and setup pages. These are used
    | by middleware for redirecting users who need to complete MFA challenges
    | or configure MFA settings.
    |
    */
    'routes' => [
        'multi_factor_challenge' => '/auth/multi-factor',
        'sudo_challenge' => '/auth/sudo',
        'multi_factor_setup' => '/settings/security',
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    |
    | Configure rate limits for MFA verification attempts to prevent brute
    | force attacks. max_attempts defines the number of failed attempts
    | allowed within the decay_minutes time window.
    |
    */
    'rate_limiting' => [
        'multi_factor_attempts' => [
            'max_attempts' => 5,
            'decay_minutes' => 5,
        ],
    ],
];
