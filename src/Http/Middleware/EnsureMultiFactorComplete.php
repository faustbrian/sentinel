<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\Http\Middleware;

use Cline\Sentinel\Sentinel;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

use function to_route;

/**
 * Middleware to ensure user has completed multi-factor authentication challenge if multi-factor authentication is enabled.
 *
 * This middleware enforces multi-factor authentication verification during the
 * session. When a user has multi-factor authentication enabled, they must complete the multi-factor authentication challenge
 * after initial authentication before accessing protected routes. This provides
 * defense-in-depth by requiring both password and second factor verification.
 *
 * Flow logic:
 * 1. If no user is authenticated, allow the request to proceed (handled by auth middleware)
 * 2. If user has no multi-factor authentication methods enabled, allow the request to proceed
 * 3. If user has multi-factor authentication enabled but hasn't completed the challenge, redirect to challenge page
 * 4. If multi-factor authentication challenge was completed this session, allow the request to proceed
 *
 * Typical usage in routes/web.php:
 * ```php
 * Route::middleware(['auth', 'multifactor.complete'])->group(function () {
 *     Route::get('/dashboard', DashboardController::class);
 *     Route::get('/settings', SettingsController::class);
 * });
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class EnsureMultiFactorComplete
{
    /**
     * Create a new middleware instance.
     *
     * @param Sentinel $sentinel The Sentinel service for checking multi-factor authentication status and session state.
     *                           Injected via Laravel's service container.
     */
    public function __construct(
        private Sentinel $sentinel,
    ) {}

    /**
     * Handle an incoming request and enforce multi-factor authentication completion.
     *
     * Checks if the authenticated user has multi-factor authentication enabled and if they have
     * completed the multi-factor authentication challenge for the current session. Users without
     * multi-factor authentication or who have already verified are allowed through. Users with
     * multi-factor authentication who haven't verified are redirected to the challenge page.
     *
     * @param  Request                    $request The incoming HTTP request
     * @param  Closure(Request): Response $next    The next middleware in the pipeline
     * @return Response                   Either the next middleware response or a redirect to the multi-factor authentication challenge
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = Auth::user();

        // Allow unauthenticated requests (handled by auth middleware)
        if ($user === null) {
            return $next($request);
        }

        // Allow users without multi-factor authentication enabled
        if (!$this->sentinel->for($user)->hasMultiFactorAuth()) {
            return $next($request);
        }

        // Allow users who have completed the multi-factor authentication challenge
        if ($this->sentinel->hasMultiFactorCompleted($request)) {
            return $next($request);
        }

        // Redirect to multi-factor authentication challenge page for users with multi-factor authentication who haven't verified
        return to_route('sentinel.challenge');
    }
}
