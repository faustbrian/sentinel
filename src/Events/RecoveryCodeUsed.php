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
 * Event dispatched when a user successfully uses a recovery code.
 *
 * This event fires when a user authenticates using one of their emergency recovery
 * codes instead of their primary multi-factor authentication method. Recovery codes are typically used when
 * the user has lost access to their authenticator app or hardware key. Each code
 * is single-use and marked as consumed after successful verification.
 *
 * The remaining count is critical for warning users when they're running low on
 * backup codes, as it indicates how many emergency access attempts they have left
 * before needing to regenerate codes.
 *
 * Use cases:
 * - Logging recovery code usage for security audits
 * - Warning users when recovery codes are running low
 * - Triggering notifications about emergency access usage
 * - Prompting users to regenerate codes if count is low
 * - Detecting potential account compromise patterns
 *
 * ```php
 * Event::listen(RecoveryCodeUsed::class, function ($event) {
 *     Log::warning('Recovery code used', [
 *         'user_id' => $event->user->id,
 *         'remaining' => $event->remaining,
 *     ]);
 *
 *     if ($event->remaining <= 2) {
 *         Notification::send($event->user, new LowRecoveryCodesAlert($event->remaining));
 *     }
 * });
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class RecoveryCodeUsed
{
    use Dispatchable;

    /**
     * Create a new recovery code used event.
     *
     * @param Authenticatable $user      The user who successfully authenticated using a
     *                                   recovery code. This indicates emergency access was
     *                                   used and may warrant additional security scrutiny.
     * @param int             $remaining The number of unused recovery codes remaining for this user.
     *                                   When this reaches 0, the user will have no emergency access
     *                                   methods available and should regenerate codes immediately.
     *                                   Typical warning threshold is 2-3 remaining codes.
     */
    public function __construct(
        public Authenticatable $user,
        public int $remaining,
    ) {}
}
