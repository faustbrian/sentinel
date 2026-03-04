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
 * Eloquent model representing a multi-factor authentication recovery code.
 *
 * Recovery codes provide emergency access to user accounts when primary multi-factor authentication methods
 * are unavailable (e.g., lost phone, damaged hardware key). Each code is single-use
 * and stored as a cryptographically hashed value for security.
 *
 * Typically, 8-10 recovery codes are generated when a user enables multi-factor authentication. Users should
 * save these codes securely (printed or password manager) for emergency use. Once a
 * code is used, it's marked with a timestamp and cannot be reused, preventing replay
 * attacks.
 *
 * Security features:
 * - Codes are hashed using bcrypt/argon2 (never stored in plaintext)
 * - Single-use enforcement via used_at timestamp
 * - UUIDs prevent enumeration attacks
 * - Invalidation support for bulk code regeneration
 *
 * @property string      $code_hash  Bcrypt hash of the recovery code (original code never stored)
 * @property Carbon      $created_at Timestamp when recovery code was generated
 * @property string      $id         UUID primary key for the recovery code
 * @property null|Carbon $used_at    Timestamp when code was consumed (null if unused)
 * @property int         $user_id    Foreign key to the owning user
 *
 * @use HasFactory<Factory<static>>
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MultiFactorRecoveryCode extends Model
{
    /** @phpstan-ignore missingType.generics */
    use HasFactory;
    use HasUuids;

    /**
     * Disable automatic timestamp management.
     *
     * We manually manage created_at and used_at timestamps for precise control
     * over code lifecycle tracking. No updated_at is needed since codes are
     * immutable after creation (only marked as used).
     *
     * @var bool
     */
    #[Override()]
    public $timestamps = false;

    /**
     * Database table name for multi-factor authentication recovery codes.
     *
     * @var string
     */
    #[Override()]
    protected $table = 'multi_factor_recovery_codes';

    /**
     * Mass assignable attributes.
     *
     * All recovery code attributes are fillable to support batch generation
     * when users enable multi-factor authentication or regenerate their recovery codes.
     *
     * @var array<int, string>
     */
    #[Override()]
    protected $fillable = [
        'user_id',
        'code_hash',
        'used_at',
        'created_at',
    ];

    /**
     * Get the user that owns this recovery code.
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
     * Defines automatic type casting for recovery code attributes:
     * - used_at: Carbon instance for tracking when code was consumed
     * - created_at: Carbon instance for tracking when code was generated
     *
     * @return array<string, string>
     */
    #[Override()]
    protected function casts(): array
    {
        return [
            'used_at' => 'datetime',
            'created_at' => 'datetime',
        ];
    }
}
