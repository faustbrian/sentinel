<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\Http\Middleware;

use Cline\Sentinel\Events\SudoModeChallenged;
use Cline\Sentinel\Sentinel;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

use function event;
use function to_route;

/**
 * Middleware to ensure sudo mode is active for sensitive operations.
 *
 * Sudo mode provides an additional security layer for highly sensitive operations
 * by requiring users to re-confirm their password within a recent time window
 * (typically 15 minutes). This prevents unauthorized actions if a user leaves
 * their authenticated session unattended, similar to how sudo works in Unix systems.
 *
 * Flow logic:
 * 1. Check if sudo mode is currently active (confirmed within the configured duration)
 * 2. If active, allow the request to proceed
 * 3. If not active, dispatch a SudoModeChallenged event for logging/monitoring
 * 4. Redirect to sudo confirmation page, preserving the intended destination URL
 *
 * Common use cases:
 * - Modifying account security settings (email, password, multi-factor authentication configuration)
 * - Financial transactions or billing changes
 * - Deleting data or accounts
 * - Granting permissions or administrative actions
 *
 * Typical usage in routes/web.php:
 * ```php
 * Route::middleware(['auth', 'sudo'])->group(function () {
 *     Route::delete('/account', [AccountController::class, 'destroy']);
 *     Route::put('/security/password', [SecurityController::class, 'updatePassword']);
 *     Route::post('/billing/payment-method', [BillingController::class, 'updatePaymentMethod']);
 * });
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class EnsureSudoMode
{
    /**
     * Create a new middleware instance.
     *
     * @param Sentinel $sentinel The Sentinel service for checking sudo mode status.
     *                           Injected via Laravel's service container.
     */
    public function __construct(
        private Sentinel $sentinel,
    ) {}

    /**
     * Handle an incoming request and enforce sudo mode.
     *
     * Verifies that sudo mode is active for the current session. If sudo mode
     * is not active, dispatches a SudoModeChallenged event and redirects the
     * user to the sudo confirmation page, preserving the intended URL for
     * post-confirmation redirect.
     *
     * @param  Request                    $request The incoming HTTP request
     * @param  Closure(Request): Response $next    The next middleware in the pipeline
     * @return Response                   Either the next middleware response or a redirect to sudo confirmation
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Allow requests when sudo mode is active
        if ($this->sentinel->inSudoMode($request)) {
            return $next($request);
        }

        // Dispatch event for logging/auditing sudo mode challenges
        $user = Auth::user();

        if ($user !== null) {
            event(
                new SudoModeChallenged($user),
            );
        }

        // Redirect to sudo confirmation, preserving intended destination
        return to_route('sentinel.sudo')
            ->with('intended', $request->fullUrl());
    }
}
