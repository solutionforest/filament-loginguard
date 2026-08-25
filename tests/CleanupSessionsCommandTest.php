<?php

use Carbon\Carbon;
use SolutionForest\FilamentLoginGuard\Models\UserSession;

beforeEach(function () {
    Carbon::setTestNow('2026-01-01 00:00:00');
});

afterEach(function () {
    Carbon::setTestNow(null);
});

it('deletes expired sessions but keeps fresh ones', function () {
    UserSession::query()->create([
        'id' => 'expired-session',
        'user_id' => 1,
        'payload' => 'test',
        'last_activity' => now()->subMinutes(121)->timestamp,
    ]);

    UserSession::query()->create([
        'id' => 'fresh-session',
        'user_id' => 2,
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    $this->artisan('filament-loginguard:cleanup-sessions')
        ->expectsOutputToContain('Deleted 1 expired rows.')
        ->assertExitCode(0);

    expect(UserSession::query()->pluck('id')->all())->toBe(['fresh-session']);
});

it('deletes everything with --all', function () {
    UserSession::query()->create([
        'id' => 'session-one',
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    UserSession::query()->create([
        'id' => 'session-two',
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    $this->artisan('filament-loginguard:cleanup-sessions', ['--all' => true])
        ->assertExitCode(0);

    expect(UserSession::query()->count())->toBe(0);
});
