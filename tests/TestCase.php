<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests;

use Cline\Sentinel\SentinelServiceProvider;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as BaseTestCase;
use Override;
use Tests\Fixtures\User;

use function base64_encode;
use function class_basename;
use function random_bytes;

/**
 * Base test case for Sentinel tests.
 *
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
abstract class TestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Factory::guessFactoryNamesUsing(
            fn (string $modelName): string => 'Tests\\Fixtures\\Factories\\'.class_basename($modelName).'Factory',
        );
    }

    /**
     * @return array<int, class-string>
     */
    #[Override()]
    protected function getPackageProviders($app): array
    {
        return [
            SentinelServiceProvider::class,
        ];
    }

    /**
     * @param Application $app
     */
    #[Override()]
    protected function getEnvironmentSetUp($app): void
    {
        $app->make(Repository::class)->set('app.key', 'base64:'.base64_encode(random_bytes(32)));

        $app->make(Repository::class)->set('database.default', 'testing');
        $app->make(Repository::class)->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $app->make(Repository::class)->set('auth.providers.users.model', User::class);

        // Run migrations
        $this->setUpDatabase($app);
    }

    /**
     * Setup the database for testing.
     */
    protected function setUpDatabase(mixed $app): void
    {
        // Create users table
        $app['db']->connection()->getSchemaBuilder()->create('users', function ($table): void {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
        });

        // Run package migrations
        $migration = include __DIR__.'/../database/migrations/create_sentinel_tables.php';
        $migration->up();
    }
}
