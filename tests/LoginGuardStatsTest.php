<?php

use Carbon\Carbon;
use Filament\Facades\Filament;
use Filament\Panel;
use Filament\Widgets\StatsOverviewWidget\Stat;
use Livewire\Livewire;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Models\LoginGuardLock;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;
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

it('counts login events in the last day and only locks that are still active', function () {
    LoginAttempt::factory()->create([
        'attempts' => 30,
        'last_attempt_at' => now()->subHour(),
        'success_count' => 50,
        'last_success_at' => now()->subHour(),
        'locked_until' => now()->addHour(),
    ]);

    foreach ([
        [SecurityEvent::TYPE_LOGIN_FAILED, now()->subDay()],
        [SecurityEvent::TYPE_LOGIN_FAILED, now()->subHour()],
        [SecurityEvent::TYPE_LOGIN_FAILED, now()],
        [SecurityEvent::TYPE_LOGIN_FAILED, now()->subDay()->subSecond()],
        [SecurityEvent::TYPE_LOGIN_SUCCEEDED, now()->subDay()],
        [SecurityEvent::TYPE_LOGIN_SUCCEEDED, now()->subDay()->subSecond()],
        [SecurityEvent::TYPE_LOCKOUT_STARTED, now()],
    ] as [$type, $occurredAt]) {
        SecurityEvent::query()->create(['type' => $type, 'occurred_at' => $occurredAt]);
    }

    foreach ([
        [LoginGuardLock::SCOPE_IP, '1.2.3.4', now()->addSecond()],
        [LoginGuardLock::SCOPE_EMAIL, 'victim@example.com', now()->addMinute()],
        [LoginGuardLock::SCOPE_PAIR, '1.2.3.4|victim@example.com', now()],
        [LoginGuardLock::SCOPE_IP, '5.6.7.8', now()->subSecond()],
    ] as [$scope, $key, $expiresAt]) {
        LoginGuardLock::query()->create([
            'scope_type' => $scope,
            'scope_key' => $key,
            'locked_until' => $expiresAt,
        ]);
    }

    $widget = Livewire::test(LoginGuardStats::class)
        ->assertSuccessful()
        ->assertSee('Failed attempts (24h)')
        ->assertSee('Locked out now')
        ->assertSee('Successful logins (24h)');

    $stats = (new ReflectionMethod($widget->instance(), 'getCachedStats'))->invoke($widget->instance());

    expect(collect($stats)->mapWithKeys(fn (Stat $stat) => [$stat->getLabel() => $stat->getValue()])->all())->toBe([
        'Failed attempts (24h)' => 3,
        'Locked out now' => 2,
        'Successful logins (24h)' => 1,
    ]);
});
