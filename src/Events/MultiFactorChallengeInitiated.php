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
 * Event dispatched when an multi-factor authentication challenge is initiated for a user.
 *
 * This event fires when a user has successfully passed the first authentication
 * factor (username/password) and is now being prompted to provide their second
 * factor (TOTP code, WebAuthn assertion, or recovery code). It marks the beginning
 * of the multi-factor authentication challenge flow.
 *
 * Use cases:
 * - Logging multi-factor authentication challenge initiation for security audits
 * - Storing challenge session data (nonce, timestamp)
 * - Sending push notifications for additional security verification
 * - Starting timers for challenge expiration
 * - Recording authentication flow metrics
 *
 * ```php
 * Event::listen(MfaChallengeInitiated::class, function ($event) {
 *     Log::info('multi-factor authentication challenge initiated', ['user_id' => $event->user->id]);
 *     session(['multi_factor_challenge_started_at' => now()]);
 * });
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class MultiFactorChallengeInitiated
{
    use Dispatchable;

    /**
     * Create a new multi-factor authentication challenge initiated event.
     *
     * @param Authenticatable $user The user for whom the multi-factor authentication challenge was initiated.
     *                              This user has passed the first factor (password) and
     *                              is now being prompted for their second factor credentials.
     */
    public function __construct(
        public Authenticatable $user,
    ) {}
}
