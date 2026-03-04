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
 * Thrown when attempting to confirm TOTP setup before initialization.
 *
 * This exception is raised when code attempts to complete the TOTP setup
 * process without first initializing it via the beginSetup() method. The
 * TOTP setup workflow requires a two-step process: first generating a
 * secret and QR code (beginSetup), then verifying the user can generate
 * valid codes before permanently enabling TOTP (confirmSetup).
 *
 * Common scenarios that trigger this exception:
 * - Calling confirmSetup() without first calling beginSetup()
 * - Session data containing the temporary TOTP secret has expired
 * - User navigates directly to confirmation step without initialization
 * - Race condition where setup state is cleared between steps
 *
 * ```php
 * // Incorrect - will throw exception
 * $sentinel->totp()->confirmSetup($user, $code);
 *
 * // Correct - initialize first, then confirm
 * $setup = $sentinel->totp()->beginSetup($user);
 * $sentinel->totp()->confirmSetup($user, $code);
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class TotpSetupNotInitializedException extends RuntimeException implements SentinelException
{
    /**
     * Create an exception for TOTP setup not initialized.
     *
     * @return self A new exception instance with an appropriate error message
     *              instructing the caller to initialize TOTP setup first.
     */
    public static function create(): self
    {
        return new self('TOTP setup has not been initialized. Call beginSetup() first.');
    }
}
