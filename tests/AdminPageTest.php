<?php

use Carbon\Carbon;
use Filament\Facades\Filament;
use Filament\Panel;
use Illuminate\Support\Facades\Gate;
use Livewire\Livewire;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Pages\LoginGuard;
use SolutionForest\FilamentLoginGuard\Tests\Support\TestCluster;
use SolutionForest\FilamentLoginGuard\Tests\Support\TestUser;

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

it('renders the blocked attempts page', function () {
    LoginAttempt::factory()->locked()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
    ]);

    Livewire::test(LoginGuard::class)
        ->assertSuccessful()
        ->assertSee('1.2.3.4');
});

it('can unblock a record', function () {
    $record = LoginAttempt::factory()->locked()->create();

    Livewire::test(LoginGuard::class)
        ->callTableAction('unblock', $record);

    $record->refresh();

    expect($record->isLocked())->toBeFalse()
        ->and($record->attempts)->toBe(0)
        ->and($record->lockout_count)->toBe(0);
});

it('can delete a record', function () {
    $record = LoginAttempt::factory()->locked()->create();

    Livewire::test(LoginGuard::class)
        ->callTableAction('delete', $record);

    expect(LoginAttempt::query()->find($record->id))->toBeNull();
});

it('denies access when the admin page is disabled', function () {
    config()->set('filament-loginguard.admin_page.enabled', false);

    Livewire::test(LoginGuard::class)
        ->assertStatus(403);
});

it('gates the page behind an ability when configured', function () {
    config()->set('filament-loginguard.admin_page.authorize', 'view-filament-loginguard');

    Gate::define('view-filament-loginguard', fn (): bool => false);

    Livewire::test(LoginGuard::class)
        ->assertStatus(403);

    Gate::define('view-filament-loginguard', fn (): bool => true);

    Livewire::test(LoginGuard::class)->assertSuccessful();
});

it('hides navigation when disabled', function () {
    config()->set('filament-loginguard.admin_page.enabled', false);

    expect(LoginGuard::shouldRegisterNavigation())->toBeFalse();
});

it('nests under a cluster when configured', function () {
    expect(LoginGuard::getCluster())->toBeNull();

    config()->set('filament-loginguard.admin_page.cluster', TestCluster::class);

    expect(LoginGuard::getCluster())->toBe(TestCluster::class);

    config()->set('filament-loginguard.admin_page.cluster', 'Not\\A\\Cluster');

    expect(LoginGuard::getCluster())->toBeNull();
});
