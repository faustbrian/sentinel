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
 * Event fired when sudo mode is enabled for a user.
 *
 * Sudo mode provides an additional security layer by requiring users to
 * re-verify their identity before performing sensitive operations. This
 * event is dispatched when a user successfully confirms their credentials
 * and sudo mode is activated for their session.
 *
 * Listeners can use this event to log security actions, notify administrators,
 * or trigger additional security workflows when privileged access is granted.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class SudoModeEnabled
{
    use Dispatchable;

    /**
     * Create a new sudo mode enabled event instance.
     *
     * @param Authenticatable $user The authenticated user for whom sudo mode was enabled.
     *                              This user has successfully re-verified their credentials
     *                              and is now granted temporary elevated access to perform
     *                              sensitive operations within the configured time window.
     */
    public function __construct(
        public Authenticatable $user,
    ) {}
}
