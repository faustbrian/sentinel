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
 * Event dispatched when a user attempts to access a sudo-protected resource.
 *
 * This event fires when a user tries to perform a sensitive operation that requires
 * recent authentication verification (sudo mode), but their sudo session has expired
 * or hasn't been established yet. Sudo mode provides an additional security layer
 * for high-risk operations by requiring users to re-verify their identity.
 *
 * Sudo mode is typically required for operations like:
 * - Changing password or email
 * - Disabling multi-factor authentication
 * - Modifying security settings
 * - Accessing sensitive account data
 * - Making irreversible changes
 *
 * Use cases:
 * - Logging sudo mode challenge attempts for security audits
 * - Redirecting users to re-authentication pages
 * - Storing the intended action for resumption after verification
 * - Tracking sensitive operation access patterns
 * - Implementing step-up authentication flows
 *
 * ```php
 * Event::listen(SudoModeChallenged::class, function ($event) {
 *     Log::info('Sudo mode challenged', ['user_id' => $event->user->id]);
 *     session(['intended_url' => url()->previous()]);
 * });
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class SudoModeChallenged
{
    use Dispatchable;

    /**
     * Create a new sudo mode challenged event.
     *
     * @param Authenticatable $user The authenticated user attempting to access a
     *                              sudo-protected resource. This user must re-verify
     *                              their credentials (password or multi-factor authentication) to establish
     *                              a sudo session before proceeding with the sensitive
     *                              operation they attempted to perform.
     */
    public function __construct(
        public Authenticatable $user,
    ) {}
}
