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
 * Event dispatched when a user successfully completes an multi-factor authentication challenge.
 *
 * This event fires after a user provides valid multi-factor authentication credentials (TOTP code, WebAuthn
 * assertion, or recovery code) during the authentication flow. It indicates that
 * the user has passed the second factor verification and should be granted access.
 *
 * Use cases:
 * - Logging successful multi-factor authentication verifications for security audits
 * - Updating last_used_at timestamps on credentials
 * - Triggering notifications about account access
 * - Clearing multi-factor authentication challenge session data
 *
 * ```php
 * Event::listen(MfaChallengeCompleted::class, function ($event) {
 *     Log::info('multi-factor authentication challenge completed', ['user_id' => $event->user->id]);
 * });
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class MultiFactorChallengeCompleted
{
    use Dispatchable;

    /**
     * Create a new multi-factor authentication challenge completed event.
     *
     * @param Authenticatable $user The user who successfully completed the multi-factor authentication challenge.
     *                              This is the authenticated user who will be granted access
     *                              to the protected resource after passing multi-factor authentication verification.
     */
    public function __construct(
        public Authenticatable $user,
    ) {}
}
