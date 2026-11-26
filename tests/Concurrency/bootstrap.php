<?php

declare(strict_types=1);

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Capsule\Manager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Schema;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardServiceProvider;
use Spatie\LaravelPackageTools\Package;

require_once dirname(__DIR__, 2) . '/vendor/autoload.php';

function concurrencyDatabase(string $directory, int $maxAttempts): Container
{
    $driver = getenv('LOGINGUARD_CONCURRENCY_CONNECTION') ?: 'sqlite';

    $connection = match ($driver) {
        'sqlite' => [
            'driver' => 'sqlite',
            'database' => $directory . '/database.sqlite',
            'busy_timeout' => 5000,
        ],
        'mysql' => [
            'driver' => 'mysql',
            'host' => getenv('LOGINGUARD_CONCURRENCY_HOST') ?: '127.0.0.1',
            'port' => getenv('LOGINGUARD_CONCURRENCY_PORT') ?: '3306',
            'database' => concurrencyMysqlDatabaseName(),
            'username' => getenv('LOGINGUARD_CONCURRENCY_USERNAME') ?: 'root',
            'password' => (string) getenv('LOGINGUARD_CONCURRENCY_PASSWORD'),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'strict' => true,
        ],
        default => throw new RuntimeException("Unsupported concurrency database driver [{$driver}]."),
    };

    $container = new Container;
    Container::setInstance($container);
    $container->instance('config', new Repository([
        'filament-loginguard' => require dirname(__DIR__, 2) . '/config/filament-loginguard.php',
    ]));
    $container['config']->set('filament-loginguard.lockout.max_attempts', $maxAttempts);

    $capsule = new Manager($container);
    $capsule->addConnection($connection);
    $capsule->bootEloquent();

    $container->instance('db', $capsule->getDatabaseManager());
    $container->bind('db.schema', fn () => $capsule->getConnection()->getSchemaBuilder());
    Facade::setFacadeApplication($container);

    if ($driver === 'mysql' && DB::selectOne('SELECT DATABASE() AS name')?->name !== $connection['database']) {
        throw new RuntimeException('The MySQL connection did not select the configured test database.');
    }

    return $container;
}

function concurrencyMysqlDatabaseName(): string
{
    $name = getenv('LOGINGUARD_CONCURRENCY_DATABASE');

    if (! is_string($name) || strlen($name) > 64 || ! preg_match('/\Aloginguard_concurrency_[a-z0-9_]+\z/', $name)) {
        throw new RuntimeException('Set LOGINGUARD_CONCURRENCY_DATABASE to an empty database named loginguard_concurrency_*.');
    }

    return $name;
}

function concurrencyMigrations(Container $container): array
{
    $schema = null;

    if (DB::connection()->getDriverName() === 'mysql') {
        $schema = concurrencyMysqlDatabaseName();

        // Keep two harnesses from claiming the same initially empty database.
        $lockName = hash('sha256', 'filament-loginguard-concurrency:' . $schema);
        $lock = DB::selectOne('SELECT GET_LOCK(?, 0) AS acquired', [$lockName]);

        if ((int) ($lock->acquired ?? 0) !== 1) {
            throw new RuntimeException('The concurrency test database is already in use.');
        }
    }

    if (Schema::getTableListing($schema) !== [] || Schema::getViews($schema) !== []) {
        throw new RuntimeException('The concurrency test database must be empty.');
    }

    $provider = new FilamentLoginGuardServiceProvider($container);
    $package = new Package;
    $provider->configurePackage($package);

    return array_map(
        fn (string $name) => require dirname(__DIR__, 2) . "/database/migrations/{$name}.php",
        $package->migrationFileNames,
    );
}
