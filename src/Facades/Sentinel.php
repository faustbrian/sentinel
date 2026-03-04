<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\Facades;

use Cline\Sentinel\RecoveryCodes\RecoveryCodeManager;
use Cline\Sentinel\Totp\TotpManager;
use Cline\Sentinel\WebAuthn\WebAuthnManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Facade;

/**
 * Laravel facade for the Sentinel multi-factor authentication service.
 *
 * This facade provides static access to the Sentinel service, enabling
 * convenient access to multi-factor authentication operations, session management, and manager
 * instances throughout your Laravel application. All methods are proxied
 * to the underlying Sentinel service instance registered in the container.
 *
 * ```php
 * // Access TOTP manager for time-based one-time passwords
 * Sentinel::totp()->beginSetup($user);
 *
 * // Access WebAuthn manager for hardware security keys
 * Sentinel::webAuthn()->beginRegistration($user, 'YubiKey');
 *
 * // Manage multi-factor authentication challenge state
 * Sentinel::initiateMultiFactorChallenge($request, $user);
 * Sentinel::markMultiFactorComplete($request);
 *
 * // Control sudo mode for sensitive operations
 * Sentinel::enableSudoMode($request);
 * $inSudoMode = Sentinel::inSudoMode($request);
 * ```
 *
 * @method static void                 clearMfaChallenge(Request $request)                           Clear multi-factor authentication challenge state from session
 * @method static void                 disableAllMfa(Authenticatable $user)                          Disable all multi-factor authentication methods for a user
 * @method static void                 enableSudoMode(Request $request)                              Enable sudo mode for current session
 * @method static Authenticatable|null getChallengedUser(Request $request)                           Get user being challenged for multi-factor authentication
 * @method static bool                 hasMfaCompleted(Request $request)                             Check if multi-factor authentication challenge completed
 * @method static void                 initiateMfaChallenge(Request $request, Authenticatable $user) Start multi-factor authentication challenge for user
 * @method static bool                 inSudoMode(Request $request)                                  Check if sudo mode is active
 * @method static void                 markMfaComplete(Request $request)                             Mark multi-factor authentication challenge as completed
 * @method static RecoveryCodeManager  recoveryCodes()                                               Get recovery code manager instance
 * @method static Carbon|null          sudoModeExpiresAt(Request $request)                           Get sudo mode expiration timestamp
 * @method static TotpManager          totp()                                                        Get TOTP manager instance
 * @method static WebAuthnManager      webAuthn()                                                    Get WebAuthn manager instance
 *
 * @author Brian Faust <brian@cline.sh>
 * @see \Cline\Sentinel\Sentinel
 */
final class Sentinel extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * Returns the service container binding key for the Sentinel service,
     * allowing Laravel's facade system to resolve the underlying instance.
     *
     * @return string The fully-qualified class name used as the container binding key
     */
    protected static function getFacadeAccessor(): string
    {
        return \Cline\Sentinel\Sentinel::class;
    }
}
