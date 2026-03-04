<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

use function to_route;

/**
 * Middleware to require users to have multi-factor authentication configured before accessing resources.
 *
 * This middleware enforces mandatory multi-factor authentication by blocking
 * access to protected routes until the user has enabled at least one multi-factor authentication method.
 * Unlike EnsureMultiFactorComplete which validates session-based multi-factor authentication challenges, this
 * middleware checks for the presence of configured multi-factor authentication credentials (TOTP,
 * WebAuthn, or recovery codes) on the user's account.
 *
 * Use cases:
 * - Organizations enforcing mandatory multi-factor authentication for all users
 * - Protecting highly sensitive resources requiring multi-factor authentication enrollment
 * - Compliance requirements mandating multi-factor authentication
 * - Admin panels or privileged sections requiring additional security
 *
 * Typical usage in routes/web.php:
 * ```php
 * Route::middleware(['auth', 'multifactor.required'])->group(function () {
 *     Route::get('/admin', AdminDashboard::class);
 *     Route::get('/billing', BillingController::class);
 * });
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class EnsureMultiFactorEnabled
{
    /**
     * Handle an incoming request and enforce multi-factor authentication enrollment.
     *
     * Checks if the authenticated user has enabled multi-factor authentication.
     * Users without multi-factor authentication configured are redirected to the setup page with an
     * error message. Users with multi-factor authentication enabled are allowed to proceed.
     *
     * @param  Request                    $request The incoming HTTP request
     * @param  Closure(Request): Response $next    The next middleware in the pipeline
     * @return Response                   Either the next middleware response or a redirect to multi-factor authentication setup
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = Auth::user();

        // Allow unauthenticated requests (handled by auth middleware)
        if ($user === null) {
            return $next($request);
        }

        // Check if user has any multi-factor authentication methods enabled
        // hasMultiFactorEnabled() is provided by HasMultiFactorAuthentication trait
        /** @phpstan-ignore-next-line method.notFound */
        if (!$user->hasMultiFactorEnabled()) {
            return to_route('sentinel.setup')
                ->with('error', 'You must enable multi-factor authentication to access this resource.');
        }

        return $next($request);
    }
}
