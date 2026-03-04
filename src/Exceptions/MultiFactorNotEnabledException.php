<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\Exceptions;

use RuntimeException;

/**
 * Thrown when multi-factor authentication operations are attempted on a user without multi-factor authentication enabled.
 *
 * This exception is thrown when the system attempts to perform multi-factor authentication-related
 * operations (verification, challenge generation, recovery code usage) on a
 * user account that hasn't enabled multi-factor authentication. This prevents
 * invalid state errors and ensures multi-factor authentication operations only occur for properly
 * configured accounts.
 *
 * Common scenarios that trigger this exception:
 * - Attempting to verify multi-factor authentication codes for a user without multi-factor authentication setup
 * - Trying to generate multi-factor authentication challenges when no credentials are registered
 * - Accessing multi-factor authentication settings or recovery codes before enabling multi-factor authentication
 * - System attempting to enforce multi-factor authentication on accounts that opted out
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MultiFactorNotEnabledException extends RuntimeException implements SentinelException
{
    /**
     * Create an exception for multi-factor authentication operations on users without multi-factor authentication enabled.
     *
     * @return self A new exception instance with an appropriate error message
     *              explaining that multi-factor authentication is not enabled for the target user.
     */
    public static function forUser(): self
    {
        return new self('Multi-factor authentication is not enabled for this user.');
    }
}
