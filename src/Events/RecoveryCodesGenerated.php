<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * Event dispatched when new recovery codes are generated for a user.
 *
 * This event fires when a user generates or regenerates their emergency recovery
 * codes. This typically occurs when:
 * - A user first enables multi-factor authentication and receives their initial set of codes
 * - A user regenerates codes after using most of their existing ones
 * - An admin manually regenerates codes for security reasons
 *
 * The plaintext recovery codes are only available during generation and should be
 * displayed to the user immediately for secure storage. After this event, only
 * hashed versions are stored in the database.
 *
 * Use cases:
 * - Logging recovery code generation for security audits
 * - Displaying codes to users for saving/printing
 * - Sending codes via secure channels (encrypted email, secure notes)
 * - Invalidating previous codes when regenerating
 * - Tracking multi-factor authentication enrollment completion
 *
 * ```php
 * Event::listen(RecoveryCodesGenerated::class, function ($event) {
 *     Log::info('Recovery codes generated', [
 *         'user_id' => $event->user->id,
 *         'count' => $event->count,
 *     ]);
 * });
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class RecoveryCodesGenerated
{
    use Dispatchable;

    /**
     * Create a new recovery codes generated event.
     *
     * @param Authenticatable $user  The user for whom recovery codes were generated.
     *                               This user should be prompted to save these codes
     *                               securely as they won't be shown again.
     * @param int             $count The number of recovery codes that were generated. Typically
     *                               8-10 codes are created to provide sufficient emergency access
     *                               options while remaining manageable for users to store securely.
     */
    public function __construct(
        public Authenticatable $user,
        public int $count,
    ) {}
}
