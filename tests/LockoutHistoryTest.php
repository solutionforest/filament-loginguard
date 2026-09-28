<?php

use Carbon\Carbon;
use SolutionForest\FilamentLoginGuard\LoginGuardService;
use SolutionForest\FilamentLoginGuard\Models\LockoutHistory;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;

beforeEach(function () {
    Carbon::setTestNow('2026-01-01 00:00:00');
    config()->set('filament-loginguard.lockout.max_attempts', 2);
});

afterEach(function () {
    Carbon::setTestNow(null);
});

it('does not delete lockout history rows', function () {
    // An expired lock + stale attempts = the row the cleanup command sweeps.
    $locked = LoginAttempt::factory()->create([
        'attempts' => 2,
        'lockout_count' => 1,
        'last_attempt_at' => now()->subMinutes(31),
        'window_started_at' => now()->subMinutes(31),
        'locked_until' => now()->subMinutes(16),
    ]);

    LockoutHistory::query()->create([
        'ip' => $locked->ip,
        'email' => $locked->email,
        'locked_at' => now()->subHours(2),
        'locked_until' => now()->subHour(),
        'lockout_count' => 1,
        'duration_minutes' => 15,
    ]);

    $this->artisan('filament-loginguard:cleanup-attempts')->assertExitCode(0);

    // The attempt row was swept, but the escalation history survives so a
    // returning attacker is not forgiven their previous lockouts.
    expect(LoginAttempt::query()->whereKey($locked->getKey())->exists())->toBeFalse()
        ->and(LockoutHistory::query()->count())->toBe(1);
});

it('resets stale attempt counters but keeps lockout_count for escalation', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    $row = LoginAttempt::factory()->create([
        'attempts' => 1,
        'lockout_count' => 3,
        'last_attempt_at' => now()->subMinutes(31),
        'window_started_at' => now()->subMinutes(31),
    ]);

    // A fresh failure after cleanup must derive its escalation from the
    // history table (3 prior lockouts), not start over.
    LockoutHistory::query()->create([
        'ip' => $row->ip,
        'email' => $row->email,
        'locked_at' => now()->subDay(),
        'locked_until' => now()->subDay()->addMinutes(15),
        'lockout_count' => 1,
        'duration_minutes' => 15,
    ]);
    LockoutHistory::query()->create([
        'ip' => $row->ip,
        'email' => $row->email,
        'locked_at' => now()->subHours(20),
        'locked_until' => now()->subHours(19),
        'lockout_count' => 2,
        'duration_minutes' => 60,
    ]);

    $this->artisan('filament-loginguard:cleanup-attempts')->assertExitCode(0);

    expect(LoginAttempt::query()->whereKey($row->getKey())->exists())->toBeFalse();

    // Trigger two fresh failures: the row is recreated and locks again at the
    // 3rd escalation step (history has 2 entries = 2 prior lockouts), not the 1st.
    request()->server->set('REMOTE_ADDR', $row->ip);
    $service = app(LoginGuardService::class);
    $service->recordFailure($row->ip, $row->email);
    $result = $service->recordFailure($row->ip, $row->email);

    expect($result->locked)->toBeTrue();

    $fresh = LoginAttempt::query()->where('ip', $row->ip)->where('email', $row->email)->sole();

    expect($fresh->lockout_count)->toBe(3)
        ->and($fresh->locked_until->equalTo(now()->addDays(3)))->toBeTrue()
        ->and(LockoutHistory::query()->count())->toBe(3);
});
