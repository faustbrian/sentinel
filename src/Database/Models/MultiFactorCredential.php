<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\Database\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Override;

use function config;

/**
 * Eloquent model representing a multi-factor authentication credential.
 *
 * Stores multi-factor authentication credentials for both TOTP (Time-based One-Time Password) and WebAuthn
 * authentication methods. Each credential contains encrypted secrets and metadata
 * specific to its authentication type.
 *
 * TOTP credentials store the shared secret used to generate time-based codes in
 * authenticator apps like Google Authenticator or Authy. WebAuthn credentials
 * store public key data for hardware security keys or platform authenticators.
 *
 * Security features:
 * - Secrets are automatically encrypted at rest using Laravel's encrypted casting
 * - UUIDs used as primary keys to prevent enumeration attacks
 * - Tracks last usage timestamp for security auditing
 * - Supports custom metadata for credential-specific configuration
 *
 * @property Carbon                    $created_at   Timestamp when credential was registered
 * @property string                    $id           UUID primary key for the credential
 * @property null|Carbon               $last_used_at Timestamp of most recent successful authentication
 * @property null|array<string, mixed> $metadata     Additional credential-specific data (e.g., WebAuthn counter, device info)
 * @property string                    $name         User-friendly name for the credential (e.g., "YubiKey 5", "Google Authenticator")
 * @property string                    $secret       Encrypted authentication secret (TOTP shared secret or WebAuthn public key)
 * @property string                    $type         Credential type: "totp" or "webauthn"
 * @property int                       $user_id      Foreign key to the owning user
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MultiFactorCredential extends Model
{
    /** @use HasFactory<Factory<static>> */
    use HasFactory;
    use HasUuids;

    /**
     * Disable automatic timestamp management.
     *
     * We manually manage created_at and last_used_at timestamps to have precise
     * control over when they're set. This prevents updated_at from being tracked
     * since credentials are immutable after creation (except for usage tracking).
     *
     * @var bool
     */
    #[Override()]
    public $timestamps = false;

    /**
     * Database table name for multi-factor authentication credentials.
     *
     * @var string
     */
    #[Override()]
    protected $table = 'multi_factor_credentials';

    /**
     * Mass assignable attributes.
     *
     * All credential attributes are fillable to support both TOTP and WebAuthn
     * enrollment flows which provide complete credential data at creation time.
     *
     * @var array<int, string>
     */
    #[Override()]
    protected $fillable = [
        'user_id',
        'type',
        'name',
        'secret',
        'metadata',
        'last_used_at',
        'created_at',
    ];

    /**
     * Get the user that owns this multi-factor authentication credential.
     *
     * Returns the relationship to the User model as configured in Laravel's
     * authentication configuration. Dynamically resolves the user model class
     * to support custom User model implementations.
     *
     * @return BelongsTo<Model, $this>
     */
    public function user(): BelongsTo
    {
        /** @var class-string<Model> $userModel */
        $userModel = config('auth.providers.users.model');

        return $this->belongsTo($userModel);
    }

    /**
     * Get the attribute casting configuration.
     *
     * Defines automatic type casting for credential attributes:
     * - secret: Encrypted at rest for security (automatically encrypted/decrypted)
     * - metadata: JSON array for flexible credential-specific data storage
     * - last_used_at: Carbon instance for convenient date manipulation
     * - created_at: Carbon instance for enrollment timestamp handling
     *
     * @return array<string, string>
     */
    #[Override()]
    protected function casts(): array
    {
        return [
            'secret' => 'encrypted',
            'metadata' => 'array',
            'last_used_at' => 'datetime',
            'created_at' => 'datetime',
        ];
    }
}
