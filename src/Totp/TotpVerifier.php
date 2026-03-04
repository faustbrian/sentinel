<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\Totp;

use Illuminate\Contracts\Config\Repository;
use PragmaRX\Google2FA\Google2FA;

use function assert;
use function is_bool;
use function is_int;

/**
 * Cryptographic service for TOTP generation and verification.
 *
 * Provides a Laravel-friendly wrapper around the Google2FA library for
 * Time-based One-Time Password (TOTP) operations. Handles secret generation
 * and code verification with configurable time window tolerance to account
 * for clock drift between server and client devices.
 *
 * The verification window allows codes from adjacent time periods to be
 * accepted, compensating for minor time synchronization issues.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class TotpVerifier
{
    /**
     * The underlying Google2FA instance for TOTP operations.
     */
    private Google2FA $google2fa;

    /**
     * Create a new TOTP verifier instance.
     *
     * @param Repository $config Laravel configuration repository providing access
     *                           to TOTP settings including time window tolerance
     *                           (sentinel.totp.window) which determines
     *                           how many 30-second periods before/after the current
     *                           time are accepted for verification.
     */
    public function __construct(
        private Repository $config,
    ) {
        $this->google2fa = new Google2FA();
    }

    /**
     * Verify a TOTP code against a secret with time window tolerance.
     *
     * Validates that the provided code matches the expected TOTP value for
     * the given secret within the configured time window. The window setting
     * allows codes from adjacent 30-second periods to be accepted, helping
     * compensate for clock drift between devices.
     *
     * For example, with window=1, codes from the previous period, current
     * period, and next period are all considered valid.
     *
     * @param string $secret The base32-encoded TOTP secret key shared between
     *                       server and authenticator app.
     * @param string $code   The 6-digit verification code entered by the user
     *                       from their authenticator application.
     *
     * @return bool True if the code is valid within the time window, false otherwise.
     */
    public function verify(string $secret, string $code): bool
    {
        // Retrieve time window tolerance from configuration (default: 1)
        $window = $this->config->get('sentinel.totp.window', 1);
        assert(is_int($window) || $window === null);

        // Verify using Google2FA library with configured window
        $result = $this->google2fa->verifyKey($secret, $code, $window);
        assert(is_bool($result));

        return $result;
    }

    /**
     * Generate a cryptographically secure TOTP secret.
     *
     * Creates a random base32-encoded secret key that will be shared between
     * the server and the user's authenticator app. This secret is the basis
     * for all future TOTP code generation.
     *
     * The generated secret should be stored encrypted in the database after
     * successful setup confirmation.
     *
     * @return string A base32-encoded random secret key suitable for TOTP use.
     */
    public function generateSecret(): string
    {
        return $this->google2fa->generateSecretKey();
    }
}
