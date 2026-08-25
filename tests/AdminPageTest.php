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
        'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
    ]);

    Livewire::test(LoginGuard::class)
        ->assertSuccessful()
        ->assertSee('1.2.3.4')
        ->assertSee('Chrome on macOS')
        ->assertDontSee('Lockouts');
});

it('shows the remaining lock time as a relative string', function () {
    LoginAttempt::factory()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'attempts' => 3,
        'locked_until' => now()->addMinutes(15),
    ]);

    Livewire::test(LoginGuard::class)
        ->assertSuccessful()
        ->assertSee('15 minutes from now');
});

it('parses user agents into device names', function () {
    $record = LoginAttempt::factory()->create([
        'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
    ]);

    expect($record->device_name)->toBe('Chrome on macOS');

    $record->update(['user_agent' => null]);

    expect($record->device_name)->toBeNull();
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

it('only offers unblock for locked records', function () {
    $locked = LoginAttempt::factory()->locked()->create();
    $tracked = LoginAttempt::factory()->create(['attempts' => 2]);

    Livewire::test(LoginGuard::class)
        ->assertTableActionVisible('unblock', $locked)
        ->assertTableActionHidden('unblock', $tracked);
});

it('offers no delete action for records', function () {
    LoginAttempt::factory()->locked()->create();

    Livewire::test(LoginGuard::class)
        ->assertSuccessful()
        ->assertActionDoesNotExist('delete');
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
