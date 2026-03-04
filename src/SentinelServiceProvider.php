<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Sentinel;

use Cline\Sentinel\Contracts\AuthenticatorAssertionValidator;
use Cline\Sentinel\Http\Middleware\EnsureMultiFactorComplete;
use Cline\Sentinel\Http\Middleware\EnsureMultiFactorEnabled;
use Cline\Sentinel\Http\Middleware\EnsureSudoMode;
use Cline\Sentinel\RecoveryCodes\RecoveryCodeGenerator;
use Cline\Sentinel\RecoveryCodes\RecoveryCodeManager;
use Cline\Sentinel\Totp\TotpManager;
use Cline\Sentinel\Totp\TotpVerifier;
use Cline\Sentinel\WebAuthn\Support\WebAuthnAssertionValidator;
use Cline\Sentinel\WebAuthn\WebAuthnManager;
use Illuminate\Routing\Router;
use Override;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

/**
 * Laravel service provider for the Sentinel multi-factor authentication package.
 *
 * This service provider handles the registration and bootstrapping of all Sentinel
 * components within the Laravel application. It registers services as singletons
 * in the container, publishes configuration and migrations, and registers middleware
 * aliases for use in routes.
 *
 * Registered services:
 * - TotpVerifier: Verifies TOTP codes against secrets
 * - TotpManager: Manages TOTP setup, verification, and lifecycle
 * - RecoveryCodeGenerator: Generates cryptographically secure recovery codes
 * - RecoveryCodeManager: Manages recovery code lifecycle and verification
 * - AuthenticatorAssertionValidator: Validates WebAuthn authentication assertions
 * - WebAuthnManager: Manages WebAuthn credential registration and verification
 * - Sentinel: Main service coordinating all multi-factor authentication operations
 *
 * Registered middleware:
 * - 'multifactor.complete': Ensures user has completed multi-factor authentication challenge
 * - 'multifactor.required': Requires user to have multi-factor authentication enabled
 * - 'sudo': Requires sudo mode confirmation for sensitive operations
 *
 * Published assets:
 * - Configuration file: config/sentinel.php
 * - Migration: create_sentinel_tables
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class SentinelServiceProvider extends PackageServiceProvider
{
    /**
     * Configure the package using Spatie's package tools.
     *
     * Sets the package name, registers the configuration file for publishing,
     * and registers the database migration. The configuration file will be
     * publishable via `php artisan vendor:publish --tag="sentinel-config"`.
     * The migration can be published and run to create required database tables.
     *
     * @param Package $package The package configuration instance
     */
    public function configurePackage(Package $package): void
    {
        $package
            ->name('sentinel')
            ->hasConfigFile()
            ->hasMigration('create_sentinel_tables');
    }

    /**
     * Register Sentinel services in the Laravel service container.
     *
     * All services are registered as singletons to ensure a single instance
     * exists throughout the request lifecycle. This improves performance and
     * ensures consistent state. Services are registered in dependency order:
     * lower-level services (verifiers, generators) before higher-level services
     * (managers) that depend on them.
     *
     * The container will automatically resolve constructor dependencies when
     * instantiating these services.
     */
    #[Override()]
    public function registeringPackage(): void
    {
        // Register TOTP services for authenticator app-based multi-factor authentication
        $this->app->singleton(TotpVerifier::class);
        $this->app->singleton(TotpManager::class);

        // Register recovery code services for backup authentication
        $this->app->singleton(RecoveryCodeGenerator::class);
        $this->app->singleton(RecoveryCodeManager::class);

        // Register WebAuthn services for hardware security key-based multi-factor authentication
        $this->app->singleton(AuthenticatorAssertionValidator::class, static fn (): WebAuthnAssertionValidator => WebAuthnAssertionValidator::createDefault());
        $this->app->singleton(WebAuthnManager::class);

        // Register main Sentinel service that coordinates all managers
        $this->app->singleton(Sentinel::class);
    }

    /**
     * Bootstrap Sentinel services after registration.
     *
     * Performs initialization tasks that must occur after all services are
     * registered. Currently registers middleware aliases with the router,
     * making them available for use in route definitions.
     */
    #[Override()]
    public function bootingPackage(): void
    {
        $this->registerMiddleware();
    }

    /**
     * Register middleware aliases with the Laravel router.
     *
     * Creates short, memorable aliases for Sentinel's middleware classes,
     * allowing them to be referenced in route definitions using simple
     * strings like 'multifactor.complete' instead of fully-qualified class names.
     *
     * Usage in routes:
     * ```php
     * Route::middleware(['auth', 'multifactor.complete'])->group(function () {
     *     Route::get('/dashboard', DashboardController::class);
     * });
     *
     * Route::middleware(['auth', 'multifactor.required'])->group(function () {
     *     Route::get('/admin', AdminController::class);
     * });
     *
     * Route::middleware(['auth', 'sudo'])->group(function () {
     *     Route::delete('/account', [AccountController::class, 'destroy']);
     * });
     * ```
     */
    private function registerMiddleware(): void
    {
        /** @var Router $router */
        $router = $this->app->make(Router::class);

        $router->aliasMiddleware('multifactor.complete', EnsureMultiFactorComplete::class);
        $router->aliasMiddleware('multifactor.required', EnsureMultiFactorEnabled::class);
        $router->aliasMiddleware('sudo', EnsureSudoMode::class);
    }
}
