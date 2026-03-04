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
 * Event fired when a user removes a WebAuthn credential.
 *
 * This event is dispatched when a user successfully removes a registered WebAuthn
 * credential from their account. This might occur when a user loses a security key,
 * replaces a device, or no longer wants to use a particular authenticator for login.
 *
 * Listeners can use this event to log security device removals, send notification
 * emails warning the user about the removed authentication method, or trigger
 * additional verification if this was the user's last remaining WebAuthn credential.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class WebAuthnCredentialRemoved
{
    use Dispatchable;

    /**
     * Create a new WebAuthn credential removed event instance.
     *
     * @param Authenticatable $user         The authenticated user who removed the credential.
     *                                      This user will no longer be able to authenticate
     *                                      using the removed WebAuthn device and should have
     *                                      alternative authentication methods available.
     * @param string          $credentialId The unique identifier of the removed credential.
     *                                      This ID corresponds to the authenticator device
     *                                      that was previously registered and is now revoked.
     */
    public function __construct(
        public Authenticatable $user,
        public string $credentialId,
    ) {}
}
