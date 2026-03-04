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
 * Thrown when recovery code verification fails.
 *
 * This exception is thrown when a user attempts to authenticate using a recovery
 * code that is either invalid, has already been used, or does not exist in the
 * system. Recovery codes are single-use backup codes provided to users when
 * enabling multi-factor authentication, allowing them to regain access if they lose their primary
 * authentication method (TOTP device, WebAuthn key, etc.).
 *
 * Common scenarios that trigger this exception:
 * - User enters a code that doesn't match any stored recovery code
 * - User attempts to reuse a recovery code that was already consumed
 * - User enters a malformed or corrupted recovery code
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidRecoveryCodeException extends RuntimeException implements SentinelException
{
    /**
     * Create an exception for invalid or already-used recovery code.
     *
     * @return self A new exception instance with an appropriate error message
     *              explaining that the recovery code verification failed.
     */
    public static function invalidCode(): self
    {
        return new self('The provided recovery code is invalid or has already been used.');
    }
}
