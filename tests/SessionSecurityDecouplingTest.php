<?php

use Carbon\Carbon;
use Filament\Facades\Filament;
use Filament\Panel;
use Illuminate\Auth\Events\Login;
use Livewire\Livewire;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;
use SolutionForest\FilamentLoginGuard\Models\KnownDevice;
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

    request()->server->set('REMOTE_ADDR', '1.2.3.4');
    request()->headers->set('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36');
});

afterEach(function () {
    Carbon::setTestNow(null);
});

it('tracks devices and enforces the concurrent limit when the admin page is disabled', function () {
    config()->set('filament-loginguard.pages.sessions.enabled', false);
    config()->set('filament-loginguard.sessions.concurrent_limit', 1);

    // A first login: the device is recorded and the concurrent limit enforced
    // even though the admin page is hidden.
    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    expect(KnownDevice::query()->count())->toBe(1);

    // The concurrent limit is enforced on sessions created by the login.
    UserSession::query()->create([
        'id' => 'session-a',
        'user_id' => 1,
        'payload' => 'test',
        'last_activity' => now()->subMinutes(5)->timestamp,
    ]);

    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    UserSession::query()->create([
        'id' => 'session-b',
        'user_id' => 1,
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    expect(UserSession::query()->where('user_id', 1)->count())->toBeLessThanOrEqual(1);
});

it('does not track session security when sessions.enabled is false', function () {
    config()->set('filament-loginguard.sessions.enabled', false);
    config()->set('filament-loginguard.sessions.concurrent_limit', 1);

    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    expect(KnownDevice::query()->count())->toBe(0);
});

it('excludes the current session from the bulk revoke', function () {
    config()->set('filament-loginguard.pages.sessions.enabled', true);

    // Laravel only accepts 40-char alnum session ids; use a valid one so the
    // store keeps it instead of silently regenerating.
    $currentId = str_repeat('a', 40);
    session()->setId($currentId);
    session()->start();

    UserSession::query()->create([
        'id' => $currentId,
        'user_id' => 42,
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    UserSession::query()->create([
        'id' => 'other-session',
        'user_id' => 42,
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    $records = UserSession::query()->whereIn('id', [$currentId, 'other-session'])->get();

    Livewire::test(UserSessions::class)
        ->callTableBulkAction('revokeMany', $records);

    expect(UserSession::query()->find($currentId))->not->toBeNull()
        ->and(UserSession::query()->find('other-session'))->toBeNull();
});
