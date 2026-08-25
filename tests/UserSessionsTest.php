<?php

use Carbon\Carbon;
use Filament\Facades\Filament;
use Filament\Panel;
use Livewire\Livewire;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;
use SolutionForest\FilamentLoginGuard\Models\UserSession;
use SolutionForest\FilamentLoginGuard\Pages\UserSessions;
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

it('renders active sessions with device and last activity', function () {
    UserSession::query()->create([
        'id' => 'session-online',
        'user_id' => 42,
        'ip_address' => '1.2.3.4',
        'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
        'payload' => 'test',
        'last_activity' => now()->subMinutes(2)->timestamp,
    ]);

    UserSession::query()->create([
        'id' => 'session-stale',
        'user_id' => 43,
        'ip_address' => '5.6.7.8',
        'payload' => 'test',
        'last_activity' => now()->subHours(2)->timestamp,
    ]);

    Livewire::test(UserSessions::class)
        ->assertSuccessful()
        ->assertSee('1.2.3.4')
        ->assertSee('Chrome on macOS')
        ->assertSee('Online now')
        ->assertSee('2 hours ago');
});

it('revokes a session', function () {
    UserSession::query()->create([
        'id' => 'session-revoke',
        'user_id' => 42,
        'ip_address' => '9.9.9.9',
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    $session = UserSession::query()->find('session-revoke');

    Livewire::test(UserSessions::class)
        ->callTableAction('revoke', $session);

    expect(UserSession::query()->find('session-revoke'))->toBeNull();
});

it('hides guest sessions without a user', function () {
    UserSession::query()->create([
        'id' => 'session-guest',
        'user_id' => null,
        'ip_address' => '1.2.3.4',
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    UserSession::query()->create([
        'id' => 'session-user',
        'user_id' => 42,
        'ip_address' => '5.6.7.8',
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    Livewire::test(UserSessions::class)
        ->assertSuccessful()
        ->assertSee('5.6.7.8')
        ->assertDontSee('1.2.3.4');
});

it('parses a user agent without a browser name', function () {
    $session = UserSession::query()->create([
        'id' => 'session-no-browser',
        'user_id' => 42,
        'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    expect($session->device_name)->toBe('macOS');
});
