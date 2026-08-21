<?php

namespace SolutionForest\FilamentLoginGuard;

use Filament\Contracts\Plugin;
use Filament\Panel;
use SolutionForest\FilamentLoginGuard\Pages\LoginGuard;

class FilamentLoginGuardPlugin implements Plugin
{
    public function getId(): string
    {
        return 'filament-loginguard';
    }

    public function register(Panel $panel): void
    {
        $panel->pages([
            LoginGuard::class,
        ]);
    }

    public function boot(Panel $panel): void
    {
        //
    }

    public static function make(): static
    {
        return app(static::class);
    }

    public static function get(): static
    {
        /** @var static $plugin */
        $plugin = filament(app(static::class)->getId());

        return $plugin;
    }
}
