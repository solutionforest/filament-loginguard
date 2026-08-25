<?php

use Carbon\Carbon;
use Filament\Facades\Filament;
use Filament\Panel;
use Livewire\Livewire;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Tests\Support\TestUser;
use SolutionForest\FilamentLoginGuard\Widgets\LoginGuardStats;

beforeEach(function () {
    Carbon::setTestNow('2026-01-01 00:00:00');

    $panel = Panel::make()
        ->id('admin')
        ->default()
        ->plugin(FilamentLoginGuardPlugin::make());

    Filament::registerPanel($panel);
    Filament::setCurrentPanel($panel);

    $this->actingAs(new TestUser);
});

afterEach(function () {
    Carbon::setTestNow(null);
});

it('renders the lockout statistics', function () {
    LoginAttempt::factory()->create([
        'attempts' => 3,
        'last_attempt_at' => now()->subHour(),
    ]);

    LoginAttempt::factory()->locked()->create([
        'attempts' => 2,
        'last_attempt_at' => now(),
    ]);

    LoginAttempt::factory()->create([
        'success_count' => 5,
        'last_success_at' => now()->subHour(),
    ]);

    Livewire::test(LoginGuardStats::class)
        ->assertSuccessful()
        ->assertSee('Failed attempts (24h)')
        ->assertSee('Locked out now')
        ->assertSee('Successful logins (24h)');
});
