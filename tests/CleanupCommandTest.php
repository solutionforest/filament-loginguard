<?php

use Carbon\Carbon;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;

beforeEach(function () {
    Carbon::setTestNow('2026-01-01 00:00:00');
});

afterEach(function () {
    Carbon::setTestNow(null);
});

it('deletes stale rows but keeps fresh and locked ones', function () {
    LoginAttempt::factory()->create([
        'last_attempt_at' => now()->subMinutes(31),
    ]);

    $fresh = LoginAttempt::factory()->create([
        'attempts' => 2,
        'last_attempt_at' => now(),
    ]);

    $locked = LoginAttempt::factory()->locked()->create([
        'last_attempt_at' => now()->subMinutes(31),
    ]);

    $this->artisan('filament-loginguard:cleanup')
        ->expectsOutputToContain('Deleted 1 stale rows.')
        ->assertExitCode(0);

    expect(LoginAttempt::query()->orderBy('id')->pluck('id')->all())
        ->toBe([$fresh->id, $locked->id]);
});

it('deletes everything with --all', function () {
    LoginAttempt::factory()->count(3)->create();

    $this->artisan('filament-loginguard:cleanup', ['--all' => true])
        ->assertExitCode(0);

    expect(LoginAttempt::query()->count())->toBe(0);
});
