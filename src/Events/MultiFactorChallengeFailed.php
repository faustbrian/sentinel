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
 * Event dispatched when a user fails to complete an multi-factor authentication challenge.
 *
 * This event fires when a user provides invalid multi-factor authentication credentials during the
 * authentication flow. This could be an incorrect TOTP code, failed WebAuthn
 * assertion, or invalid recovery code. It's critical for security monitoring
 * and rate limiting to prevent brute force attacks.
 *
 * Use cases:
 * - Logging failed multi-factor authentication attempts for security audits
 * - Implementing rate limiting and account lockout policies
 * - Triggering fraud detection alerts for suspicious patterns
 * - Tracking failed attempts to warn users of potential account compromise
 * - Incrementing failure counters for progressive delays
 *
 * ```php
 * Event::listen(MfaChallengeFailed::class, function ($event) {
 *     Log::warning('multi-factor authentication challenge failed', [
 *         'user_id' => $event->user->id,
 *         'method' => $event->method,
 *     ]);
 *     RateLimiter::hit('multifactor-attempts:' . $event->user->id);
 * });
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class MultiFactorChallengeFailed
{
    use Dispatchable;

    /**
     * Create a new multi-factor authentication challenge failed event.
     *
     * @param Authenticatable $user   The user who failed the multi-factor authentication challenge.
     *                                Used for security logging, rate limiting, and
     *                                tracking failed authentication attempts per account.
     * @param string          $method The multi-factor authentication method that failed verification. Values include
     *                                "totp" for authenticator app codes, "webauthn" for hardware
     *                                keys, or "recovery" for recovery codes. Useful for identifying
     *                                which authentication method is experiencing issues.
     */
    public function __construct(
        public Authenticatable $user,
        public string $method,
    ) {}
}
