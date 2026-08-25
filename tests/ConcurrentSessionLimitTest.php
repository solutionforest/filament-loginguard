<?php

use Carbon\Carbon;
use Illuminate\Auth\Events\Login;
use SolutionForest\FilamentLoginGuard\Models\UserSession;
use SolutionForest\FilamentLoginGuard\Tests\Support\TestUser;

beforeEach(function () {
    Carbon::setTestNow('2026-01-01 00:00:00');

    request()->server->set('REMOTE_ADDR', '1.2.3.4');
});

afterEach(function () {
    Carbon::setTestNow(null);
});

it('evicts the oldest sessions beyond the concurrent limit', function () {
    config()->set('filament-loginguard.sessions.concurrent_limit', 2);

    UserSession::query()->create([
        'id' => 'oldest-session',
        'user_id' => 1,
        'payload' => 'test',
        'last_activity' => now()->subMinutes(10)->timestamp,
    ]);

    UserSession::query()->create([
        'id' => 'newer-session',
        'user_id' => 1,
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    event(new Login('web', new TestUser, false));

    expect(UserSession::query()->where('user_id', 1)->pluck('id')->all())
        ->toBe(['newer-session']);
});

it('keeps sessions when the limit is not configured', function () {
    UserSession::query()->create([
        'id' => 'session-a',
        'user_id' => 1,
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    event(new Login('web', new TestUser, false));

    expect(UserSession::query()->where('user_id', 1)->count())->toBe(1);
});
