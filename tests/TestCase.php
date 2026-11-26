<?php

namespace SolutionForest\FilamentLoginGuard\Tests;

use BladeUI\Heroicons\BladeHeroiconsServiceProvider;
use BladeUI\Icons\BladeIconsServiceProvider;
use Filament\Actions\ActionsServiceProvider;
use Filament\FilamentServiceProvider;
use Filament\Forms\FormsServiceProvider;
use Filament\Infolists\InfolistsServiceProvider;
use Filament\Notifications\NotificationsServiceProvider;
use Filament\Schemas\SchemasServiceProvider;
use Filament\Support\SupportServiceProvider;
use Filament\Tables\TablesServiceProvider;
use Filament\Widgets\WidgetsServiceProvider;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Laravel\Fortify\FortifyServiceProvider;
use Livewire\LivewireServiceProvider;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase as Orchestra;
use PDO;
use Pdo\Mysql;
use RyanChandler\BladeCaptureDirective\BladeCaptureDirectiveServiceProvider;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardServiceProvider;

class TestCase extends Orchestra
{
    use LazilyRefreshDatabase;
    use WithWorkbench;

    protected function setUp(): void
    {
        parent::setUp();

        Factory::guessFactoryNamesUsing(
            fn (string $modelName) => 'SolutionForest\\FilamentLoginGuard\\Database\\Factories\\' . class_basename($modelName) . 'Factory'
        );
    }

    protected function getPackageProviders($app)
    {
        $providers = [
            ActionsServiceProvider::class,
            BladeCaptureDirectiveServiceProvider::class,
            BladeHeroiconsServiceProvider::class,
            BladeIconsServiceProvider::class,
            FilamentServiceProvider::class,
            FormsServiceProvider::class,
            InfolistsServiceProvider::class,
            LivewireServiceProvider::class,
            NotificationsServiceProvider::class,
            SchemasServiceProvider::class,
            SupportServiceProvider::class,
            TablesServiceProvider::class,
            WidgetsServiceProvider::class,
            FilamentLoginGuardServiceProvider::class,
            FortifyServiceProvider::class,
            \Workbench\App\Providers\FortifyServiceProvider::class,
        ];

        sort($providers);

        return $providers;
    }

    public function getEnvironmentSetUp($app): void
    {
        // The normal suite is in-memory SQLite. CI can run the same assertions
        // against a real database, including strict lengths and SQL dialects.
        $connection = env('LOGINGUARD_TEST_CONNECTION', 'testing');
        if ($connection !== 'testing') {
            if ($connection !== 'mysql') {
                throw new \InvalidArgumentException('LOGINGUARD_TEST_CONNECTION must be testing or mysql.');
            }

            $database = env('LOGINGUARD_TEST_DATABASE', 'loginguard_test');
            if (! is_string($database) || strlen($database) > 64 || ! preg_match('/\Aloginguard_test(?:_[a-z0-9_]+)?\z/', $database)) {
                throw new \InvalidArgumentException('Use a disposable database named loginguard_test or loginguard_test_*.');
            }

            if (! extension_loaded('pdo_mysql')) {
                throw new \RuntimeException('The MySQL test connection requires pdo_mysql.');
            }

            $initCommand = PHP_VERSION_ID >= 80400 ? Mysql::ATTR_INIT_COMMAND : PDO::MYSQL_ATTR_INIT_COMMAND;

            // Never inherit DB_URL or application credentials: migrate:fresh
            // must only target the explicitly selected disposable test schema.
            $connection = 'loginguard_mysql';
            $app['config']->set('database.connections.' . $connection, [
                'driver' => 'mysql',
                'host' => env('LOGINGUARD_TEST_HOST', '127.0.0.1'),
                'port' => env('LOGINGUARD_TEST_PORT', '3306'),
                'database' => $database,
                'username' => env('LOGINGUARD_TEST_USERNAME', 'root'),
                'password' => env('LOGINGUARD_TEST_PASSWORD', ''),
                'charset' => 'utf8mb4',
                'collation' => 'utf8mb4_unicode_ci',
                'strict' => true,
                'options' => [
                    PDO::ATTR_TIMEOUT => 5,
                    // Expose blocked schema and row operations before the CI job times out.
                    $initCommand => 'SET SESSION lock_wait_timeout = 10, SESSION innodb_lock_wait_timeout = 10',
                ],
            ]);
        }

        $app['config']->set('database.default', $connection);
        $app['config']->set('app.key', 'base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');

        // Filament's export jobs use Bus::batch(), which stores batch records in
        // the connection from queue.batching.database — the sqlite connection by
        // default, which requires a physical database.sqlite file that does not
        // exist in CI. Point it at the suite's selected connection instead.
        $app['config']->set('queue.batching.database', $connection);
    }

    protected function defineDatabaseMigrations(): void
    {
        // The package service provider auto-loads the plugin migrations
        // (runsMigrations), so nothing extra is registered here — except the
        // `exports` table, which Filament ships as an app-level migration and
        // which the CSV export feature writes to.
        $this->loadMigrationsFrom(__DIR__ . '/Support/migrations');
    }
}
