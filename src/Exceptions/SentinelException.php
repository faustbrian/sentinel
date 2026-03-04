<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\Exceptions;

use Throwable;

/**
 * Marker interface for all Sentinel package exceptions.
 *
 * This interface serves as a common type for all exceptions thrown by the
 * Sentinel package, enabling consumers to catch and handle all package-specific
 * exceptions with a single catch block. This follows the best practice of
 * providing a package-level exception hierarchy for better error handling.
 *
 * Implementing classes include:
 * - InvalidRecoveryCodeException - Recovery code verification failures
 * - InvalidTotpCodeException - TOTP code verification failures
 * - InvalidWebAuthnAssertionException - WebAuthn assertion verification failures
 * - MfaNotEnabledException - multi-factor authentication operations on accounts without multi-factor authentication
 *
 * ```php
 * try {
 *     $mfaService->verifyTotp($user, $code);
 * } catch (SentinelException $e) {
 *     // Handle any Sentinel-specific exception
 *     Log::warning('multi-factor authentication verification failed', ['error' => $e->getMessage()]);
 * }
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface SentinelException extends Throwable {}
