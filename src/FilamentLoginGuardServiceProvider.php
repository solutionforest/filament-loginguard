<?php

namespace SolutionForest\FilamentLoginGuard;

use Filament\Support\Assets\Asset;
use Filament\Support\Facades\FilamentAsset;
use Filament\Support\Facades\FilamentIcon;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Filesystem\Filesystem;
use Livewire\Features\SupportTesting\Testable;
use SolutionForest\FilamentLoginGuard\Commands\CleanupCommand;
use SolutionForest\FilamentLoginGuard\Commands\CleanupSessionsCommand;
use SolutionForest\FilamentLoginGuard\Listeners\AuthenticationListener;
use SolutionForest\FilamentLoginGuard\Testing\TestsFilamentLoginGuard;
use Spatie\LaravelPackageTools\Commands\InstallCommand;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class FilamentLoginGuardServiceProvider extends PackageServiceProvider
{
    public static string $name = 'filament-loginguard';

    public static string $viewNamespace = 'filament-loginguard';

    public function configurePackage(Package $package): void
    {
        /*
         * This class is a Package Service Provider
         *
         * More info: https://github.com/spatie/laravel-package-tools
         */
        $package->name(static::$name)
            ->hasConfigFile('filament-loginguard')
            ->hasMigrations($this->getMigrations())
            ->hasTranslations()
            ->hasViews(static::$viewNamespace)
            ->hasCommands($this->getCommands())
            ->hasInstallCommand(function (InstallCommand $command) {
                $command
                    ->publishConfigFile()
                    ->publishMigrations()
                    ->askToRunMigrations()
                    ->askToStarRepoOnGitHub('solutionforest/filament-loginguard');
            });
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(LoginGuardService::class);
    }

    public function packageBooted(): void
    {
        // Asset Registration
        FilamentAsset::register(
            $this->getAssets(),
            $this->getAssetPackageName()
        );

        FilamentAsset::registerScriptData(
            $this->getScriptData(),
            $this->getAssetPackageName()
        );

        // Icon Registration
        FilamentIcon::register($this->getIcons());

        // Handle Stubs
        if (app()->runningInConsole()) {
            foreach (app(Filesystem::class)->files(__DIR__ . '/../stubs/') as $file) {
                $this->publishes([
                    $file->getRealPath() => base_path("stubs/filament-loginguard/{$file->getFilename()}"),
                ], 'filament-loginguard-stubs');
            }
        }

        // Testing
        Testable::mixin(new TestsFilamentLoginGuard);

        // Brute force protection listeners
        $events = $this->app->make(Dispatcher::class);

        $events->listen(Attempting::class, [AuthenticationListener::class, 'handleAttempting']);
        $events->listen(Failed::class, [AuthenticationListener::class, 'handleFailed']);
        $events->listen(Login::class, [AuthenticationListener::class, 'handleLogin']);
    }

    protected function getAssetPackageName(): ?string
    {
        return 'solution-forest/filament-loginguard';
    }

    /**
     * @return array<Asset>
     */
    protected function getAssets(): array
    {
        return [];
    }

    /**
     * @return array<class-string>
     */
    protected function getCommands(): array
    {
        return [
            CleanupCommand::class,
            CleanupSessionsCommand::class,
        ];
    }

    /**
     * @return array<string>
     */
    protected function getIcons(): array
    {
        return [];
    }

    /**
     * @return array<string>
     */
    protected function getRoutes(): array
    {
        return [];
    }

    /**
     * @return array<string, mixed>
     */
    protected function getScriptData(): array
    {
        return [];
    }

    /**
     * @return array<string>
     */
    protected function getMigrations(): array
    {
        return [
            'create_filament_loginguard_attempts_table',
            'update_filament_loginguard_attempts_table_add_user_agent',
            'update_filament_loginguard_attempts_table_add_success',
            'create_filament_loginguard_known_devices_table',
        ];
    }
}
