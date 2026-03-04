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
 * Event fired when a user disables TOTP authentication.
 *
 * This event is dispatched when a user successfully disables Time-based
 * One-Time Password (TOTP) authentication for their account. TOTP is a
 * common two-factor authentication method using authenticator apps like
 * Google Authenticator or Authy.
 *
 * Listeners can use this event to log security changes, send notification
 * emails to the user warning them about the reduced security level, or
 * trigger additional verification steps before allowing the change.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class TotpDisabled
{
    use Dispatchable;

    /**
     * Create a new TOTP disabled event instance.
     *
     * @param Authenticatable $user The authenticated user who disabled TOTP authentication.
     *                              This user's account will no longer require TOTP codes
     *                              during login, reducing their account security level from
     *                              two-factor authentication to single-factor authentication.
     */
    public function __construct(
        public Authenticatable $user,
    ) {}
}
