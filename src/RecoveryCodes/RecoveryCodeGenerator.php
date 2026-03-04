<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\RecoveryCodes;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Str;

use function chunk_split;
use function mb_rtrim;
use function mb_strtoupper;

/**
 * Generates cryptographically secure recovery codes for multi-factor authentication backup access.
 *
 * Recovery codes are single-use backup credentials that allow users to regain
 * access to their account if they lose their primary multi-factor authentication device (authenticator
 * app, security key, etc.). Each code is generated using Laravel's cryptographically
 * secure random string generator and formatted for readability.
 *
 * Code format: XXXXX-XXXXX (e.g., "AB3D9-K2M4P")
 * - Uppercase alphanumeric characters for clarity
 * - Hyphen separator every 5 characters for easier manual entry
 * - Configurable length (default: 10 characters)
 * - Configurable count (default: 8 codes)
 *
 * Security considerations:
 * - Codes are only shown once during generation
 * - Stored as bcrypt hashes in database (never plain text)
 * - Automatically invalidated after use
 * - All existing codes invalidated when new set is generated
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class RecoveryCodeGenerator
{
    /**
     * Create a new recovery code generator instance.
     *
     * @param Repository $config Laravel configuration repository for accessing recovery
     *                           code settings (count, length). Injected via container.
     */
    public function __construct(
        private Repository $config,
    ) {}

    /**
     * Generate a set of recovery codes.
     *
     * Creates multiple recovery codes based on the configured count. Each code
     * is cryptographically secure and formatted for readability. The number of
     * codes generated is controlled by the 'sentinel.recovery_codes.count'
     * configuration value.
     *
     * ```php
     * $generator = app(RecoveryCodeGenerator::class);
     * $codes = $generator->generate();
     * // Returns: ["AB3D9-K2M4P", "XY7Z1-QW8E4", ...]
     * ```
     *
     * @return array<int, string> Array of formatted recovery codes in plain text.
     *                            These should be displayed to the user once and
     *                            then hashed before storage.
     */
    public function generate(): array
    {
        $count = $this->config->get('sentinel.recovery_codes.count', 8);
        $codes = [];

        for ($i = 0; $i < $count; ++$i) {
            $codes[] = $this->generateSingleCode();
        }

        return $codes;
    }

    /**
     * Generate a single formatted recovery code.
     *
     * Creates one cryptographically secure recovery code using Laravel's Str::random()
     * method, which uses PHP's random_bytes() for cryptographic randomness. The code
     * is converted to uppercase and formatted with hyphens for readability.
     *
     * Formatting process:
     * 1. Generate random alphanumeric string of configured length
     * 2. Convert to uppercase (avoids ambiguous characters in display)
     * 3. Split into 5-character chunks separated by hyphens
     * 4. Remove trailing hyphen if present
     *
     * @return string A formatted recovery code like "ABCD5-6789E" (exact format
     *                depends on configured length, default produces XXXXX-XXXXX)
     */
    private function generateSingleCode(): string
    {
        /** @var int $length */
        $length = $this->config->get('sentinel.recovery_codes.length', 10);

        // Generate cryptographically secure random string
        $code = mb_strtoupper(Str::random($length));

        // Format with hyphen every 5 characters for readability
        return mb_rtrim(chunk_split($code, 5, '-'), '-');
    }
}
