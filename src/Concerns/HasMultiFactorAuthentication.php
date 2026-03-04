<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\Concerns;

use Cline\Sentinel\Database\Models\MultiFactorCredential;
use Cline\Sentinel\Database\Models\MultiFactorRecoveryCode;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * Provides multi-factor authentication relationships and status checking for User models.
 *
 * This trait adds the necessary Eloquent relationships and helper methods to enable
 * multi-factor authentication functionality on any User model. It provides access to multi-factor authentication credentials
 * (TOTP and WebAuthn) and recovery codes through Laravel's relationship system.
 *
 * All business logic for multi-factor authentication operations (enabling, verifying, disabling) is handled
 * by the Sentinel facade and dedicated manager classes, keeping this trait focused
 * solely on data access relationships.
 *
 * ```php
 * class User extends Authenticatable
 * {
 *     use HasMultiFactorAuthentication;
 * }
 *
 * // Access relationships
 * $user->multiFactorCredentials; // All multi-factor authentication credentials
 * $user->multiFactorRecoveryCodes; // All recovery codes
 * $user->hasMultiFactorEnabled(); // Check if multi-factor authentication is active
 * ```
 *
 * @mixin Model
 *
 * @author Brian Faust <brian@cline.sh>
 */
trait HasMultiFactorAuthentication
{
    /**
     * Get all multi-factor authentication credentials associated with this user.
     *
     * Returns all authentication credentials including TOTP secrets and WebAuthn
     * public key credentials. Each credential stores encrypted authentication data
     * and metadata about the multi-factor authentication method.
     *
     * @return HasMany<MultiFactorCredential, $this>
     */
    public function multiFactorCredentials(): HasMany
    {
        return $this->hasMany(MultiFactorCredential::class, 'user_id');
    }

    /**
     * Get all recovery codes associated with this user.
     *
     * Returns both used and unused recovery codes. Recovery codes provide emergency
     * access when primary multi-factor authentication methods are unavailable. Each code is single-use and
     * marked with a timestamp when consumed.
     *
     * @return HasMany<MultiFactorRecoveryCode, $this>
     */
    public function multiFactorRecoveryCodes(): HasMany
    {
        return $this->hasMany(MultiFactorRecoveryCode::class, 'user_id');
    }

    /**
     * Determine if the user has any multi-factor authentication method enabled.
     *
     * Checks for the existence of at least one multi-factor authentication credential (TOTP or WebAuthn).
     * This is a convenience method for quickly determining if multi-factor authentication is active without
     * loading all credential records.
     *
     * @return bool True if user has at least one active multi-factor authentication credential
     */
    public function hasMultiFactorEnabled(): bool
    {
        return $this->multiFactorCredentials()->exists();
    }
}
