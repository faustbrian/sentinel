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
 * Thrown when attempting to confirm WebAuthn setup before initialization.
 *
 * This exception is raised when code attempts to complete the WebAuthn
 * registration process without first initializing it via the beginRegistration()
 * method. The WebAuthn registration workflow requires a two-step process:
 * first generating a registration challenge and public key credential creation
 * options (beginRegistration), then verifying the authenticator's response
 * before storing the credential (confirmRegistration).
 *
 * Common scenarios that trigger this exception:
 * - Calling confirmRegistration() without first calling beginRegistration()
 * - Session data containing the challenge has expired or been cleared
 * - User navigates directly to confirmation endpoint without initialization
 * - Race condition where registration state is cleared between steps
 * - Multiple concurrent registration attempts interfering with each other
 *
 * ```php
 * // Incorrect - will throw exception
 * $sentinel->webAuthn()->confirmRegistration($user, $response);
 *
 * // Correct - initialize first, then confirm
 * $options = $sentinel->webAuthn()->beginRegistration($user, 'Security Key');
 * // ... user interacts with authenticator in browser ...
 * $sentinel->webAuthn()->confirmRegistration($user, $response);
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class WebAuthnSetupNotInitializedException extends RuntimeException implements SentinelException
{
    /**
     * Create an exception for WebAuthn setup not initialized.
     *
     * @return self A new exception instance with an appropriate error message
     *              instructing the caller to initialize WebAuthn registration first.
     */
    public static function create(): self
    {
        return new self('WebAuthn setup has not been initialized. Call beginRegistration() first.');
    }
}
