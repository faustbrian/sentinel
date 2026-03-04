<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\RecoveryCodes;

use Cline\Sentinel\Database\Models\MultiFactorRecoveryCode;
use Cline\Sentinel\Events\RecoveryCodesGenerated;
use Cline\Sentinel\Events\RecoveryCodeUsed;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

use function count;
use function event;
use function now;

/**
 * Manages recovery code generation, verification, and lifecycle.
 *
 * This manager handles the complete lifecycle of recovery codes: generation,
 * storage, verification, and invalidation. Recovery codes serve as backup
 * authentication credentials, allowing users to regain access when they lose
 * their primary multi-factor authentication device (authenticator app, security key, etc.).
 *
 * Security features:
 * - Codes stored as bcrypt hashes, never plain text
 * - Single-use only - automatically marked as used upon successful verification
 * - All existing codes invalidated when regenerating new set
 * - Constant-time comparison via Hash::check prevents timing attacks
 * - Events dispatched for auditing and monitoring
 *
 * Typical workflow:
 * ```php
 * // Generate codes when enabling multi-factor authentication
 * $codes = Sentinel::recoveryCodes()->generate($user);
 * // Display $codes to user (only chance to see them)
 *
 * // Verify code during login
 * if (Sentinel::recoveryCodes()->verify($user, $inputCode)) {
 *     Auth::login($user);
 * }
 *
 * // Check remaining codes
 * $remaining = Sentinel::recoveryCodes()->remaining($user);
 * if ($remaining < 3) {
 *     // Prompt user to regenerate codes
 * }
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class RecoveryCodeManager
{
    /**
     * Create a new recovery code manager instance.
     *
     * @param RecoveryCodeGenerator $generator Service for generating cryptographically
     *                                         secure recovery codes. Injected via container.
     */
    public function __construct(
        private RecoveryCodeGenerator $generator,
    ) {}

    /**
     * Generate new recovery codes for a user.
     *
     * Creates a fresh set of recovery codes, invalidating all existing codes
     * for security. The generated codes are returned in plain text and must
     * be displayed to the user immediately, as they cannot be retrieved later
     * (only hashed versions are stored). Dispatches RecoveryCodesGenerated
     * event for auditing.
     *
     * Important: All existing recovery codes are permanently deleted before
     * generating new ones. This prevents code accumulation and ensures users
     * always have a current, known set of codes.
     *
     * @param  Authenticatable    $user The user to generate recovery codes for
     * @return array<int, string> Plain text recovery codes that must be shown to the user.
     *                            Format: ["ABCD5-6789E", "XY7Z1-QW8E4", ...].
     *                            Store these securely - they cannot be retrieved later.
     */
    public function generate(Authenticatable $user): array
    {
        // Delete all existing recovery codes for this user
        $this->invalidate($user);

        // Generate new set of cryptographically secure codes
        $codes = $this->generator->generate();

        // Store hashed versions in database (never store plain text)
        foreach ($codes as $code) {
            MultiFactorRecoveryCode::query()->create([
                'id' => Str::uuid()->toString(),
                'user_id' => $user->getAuthIdentifier(),
                'code_hash' => Hash::make($code),
                'created_at' => now(),
            ]);
        }

        // Dispatch event for auditing/logging
        event(
            new RecoveryCodesGenerated($user, count($codes)),
        );

        return $codes;
    }

    /**
     * Verify and consume a recovery code.
     *
     * Checks if the provided code matches any unused recovery code for the user.
     * Uses constant-time comparison via Hash::check to prevent timing attacks.
     * If valid, the code is marked as used and cannot be reused. Dispatches
     * RecoveryCodeUsed event with remaining code count for monitoring.
     *
     * This method only searches through unused codes for efficiency and security.
     * Once a code is verified, it's immediately marked with a 'used_at' timestamp
     * and excluded from future verification attempts.
     *
     * @param  Authenticatable $user The user attempting to authenticate
     * @param  string          $code The recovery code provided by the user (plain text)
     * @return bool            True if the code is valid and unused, false if invalid or already used
     */
    public function verify(Authenticatable $user, string $code): bool
    {
        /** @var Collection<int, MultiFactorRecoveryCode> $recoveryCodes */
        $recoveryCodes = MultiFactorRecoveryCode::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->whereNull('used_at')
            ->get();

        // Check each unused code using constant-time comparison
        foreach ($recoveryCodes as $recoveryCode) {
            if (Hash::check($code, $recoveryCode->code_hash)) {
                // Mark code as used to prevent reuse
                $recoveryCode->update(['used_at' => now()]);

                // Dispatch event with remaining code count for monitoring
                $remaining = $this->remaining($user);
                event(
                    new RecoveryCodeUsed($user, $remaining),
                );

                return true;
            }
        }

        return false;
    }

    /**
     * Get the count of unused recovery codes for a user.
     *
     * Returns the number of recovery codes that are still available for use.
     * This is useful for warning users when they're running low on codes
     * and should regenerate a new set. Applications typically prompt users
     * to regenerate when fewer than 2-3 codes remain.
     *
     * @param  Authenticatable $user The user to check recovery code count for
     * @return int             Number of unused recovery codes available (0 or more)
     */
    public function remaining(Authenticatable $user): int
    {
        return MultiFactorRecoveryCode::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->whereNull('used_at')
            ->count();
    }

    /**
     * Invalidate all recovery codes for a user.
     *
     * Permanently deletes all recovery codes (both used and unused) for the
     * specified user. This is called automatically when generating new codes,
     * and can also be invoked when disabling multi-factor authentication entirely. No events are
     * dispatched - this is a low-level operation.
     *
     * @param Authenticatable $user The user whose recovery codes should be deleted
     */
    public function invalidate(Authenticatable $user): void
    {
        MultiFactorRecoveryCode::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->delete();
    }
}
