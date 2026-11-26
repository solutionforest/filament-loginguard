<?php

use Carbon\Carbon;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Event;
use Illuminate\Validation\ValidationException;
use SolutionForest\FilamentLoginGuard\Events\LoginLockedOut;
use SolutionForest\FilamentLoginGuard\LoginGuardService;
use SolutionForest\FilamentLoginGuard\Models\LockoutHistory;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Models\LoginGuardLock;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;
use SolutionForest\FilamentLoginGuard\Tests\Support\TestUser;

beforeEach(function () {
    Carbon::setTestNow('2026-01-01 00:00:00');
    request()->server->set('REMOTE_ADDR', '1.2.3.4');
    request()->headers->set('User-Agent', 'Mozilla/5.0 (TestBrowser) Chrome/151.0.0.0');
    config()->set('filament-loginguard.lockout.whitelist.ips', []);
    config()->set('filament-loginguard.lockout.notifications.enabled', false);

    // Dispatch a Failed event, swallowing the ValidationException that lockout-triggering
    // attempts throw by design.
    $this->failed = function (string $email = 'a@example.com', string $guard = 'web'): void {
        try {
            event(new Failed($guard, null, ['email' => $email, 'password' => 'x']));
        } catch (ValidationException) {
            // Expected when this attempt crosses the lockout threshold.
        }
    };
});

afterEach(function () {
    Carbon::setTestNow(null);
});

it('records failed attempts', function () {
    ($this->failed)();
    ($this->failed)();
    ($this->failed)();

    $row = LoginAttempt::query()->sole();

    expect($row->ip)->toBe('1.2.3.4')
        ->and($row->email)->toBe('a@example.com')
        ->and($row->attempts)->toBe(3)
        ->and($row->user_agent)->toBe('Mozilla/5.0 (TestBrowser) Chrome/151.0.0.0')
        ->and($row->last_attempt_at->equalTo(now()))->toBeTrue()
        ->and($row->isLocked())->toBeFalse();
});

it('fits the stored user agent within the 255-character column', function (string $userAgent, string $expected) {
    request()->headers->set('User-Agent', $userAgent);

    ($this->failed)();

    expect(LoginAttempt::query()->sole()->user_agent)->toBe($expected);
})->with([
    'already fits' => [str_repeat('x', 255), str_repeat('x', 255)],
    'overlong ASCII' => [str_repeat('x', 300), str_repeat('x', 252) . '...'],
    'overlong Unicode' => [str_repeat('é', 300), str_repeat('é', 252) . '...'],
]);

it('locks out when the max attempts are reached', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 3);

    ($this->failed)();
    ($this->failed)();

    expect(app(LoginGuardService::class)->isLocked('1.2.3.4', 'a@example.com'))->toBeFalse();

    ($this->failed)();

    $service = app(LoginGuardService::class);

    expect($service->isLocked('1.2.3.4', 'a@example.com'))->toBeTrue()
        ->and(LoginGuardLock::query()->where('scope_type', LoginGuardLock::SCOPE_IP)->where('scope_key', '1.2.3.4')->exists())->toBeTrue()
        ->and(LoginGuardLock::query()->where('scope_type', LoginGuardLock::SCOPE_EMAIL)->where('scope_key', 'a@example.com')->exists())->toBeTrue()
        ->and(LoginGuardLock::query()->where('scope_type', LoginGuardLock::SCOPE_IP)->where('scope_key', '1.2.3.4')->first()->locked_until->equalTo(now()->addMinutes(15)))->toBeTrue()
        ->and($service->lockFor('1.2.3.4', 'a@example.com')->equalTo(now()->addMinutes(15)))->toBeTrue();
});

it('rejects locked keys before credential work', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    ($this->failed)();
    ($this->failed)();

    try {
        event(new Attempting('web', ['email' => 'a@example.com', 'password' => 'x'], false));
        $this->fail('Expected a ValidationException');
    } catch (ValidationException $exception) {
        expect($exception->errors())->toHaveKeys(['data.email', 'email'])
            ->and($exception->errors()['email'][0])->toContain('15');
    }
});

it('escalates lockout durations', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 3);

    // First lockout: 15 minutes.
    for ($i = 0; $i < 3; $i++) {
        ($this->failed)();
    }

    expect(LoginGuardLock::query()->where('scope_type', LoginGuardLock::SCOPE_IP)->where('scope_key', '1.2.3.4')->first()->escalation_count)->toBe(1);

    // Second lockout: 24 hours.
    Carbon::setTestNow(now()->addMinutes(16));

    for ($i = 0; $i < 3; $i++) {
        ($this->failed)();
    }

    expect(LoginGuardLock::query()->where('scope_type', LoginGuardLock::SCOPE_IP)->where('scope_key', '1.2.3.4')->first()->locked_until->equalTo(now()->addHours(24)))->toBeTrue();

    // Third lockout: 72 hours.
    Carbon::setTestNow(now()->addDay()->addMinutes(1));

    for ($i = 0; $i < 3; $i++) {
        ($this->failed)();
    }

    expect(LoginGuardLock::query()->where('scope_type', LoginGuardLock::SCOPE_IP)->where('scope_key', '1.2.3.4')->first()->locked_until->equalTo(now()->addHours(72)))->toBeTrue();
});

it('computes escalation durations and caps at the last ban', function () {
    $service = app(LoginGuardService::class);

    expect($service->durationForLockoutCount(1))->toBe(15)
        ->and($service->durationForLockoutCount(2))->toBe(24 * 60)
        ->and($service->durationForLockoutCount(3))->toBe(72 * 60)
        ->and($service->durationForLockoutCount(4))->toBe(168 * 60)
        ->and($service->durationForLockoutCount(9))->toBe(168 * 60);

    config()->set('filament-loginguard.lockout.escalation_hours', []);

    expect($service->durationForLockoutCount(2))->toBe(15);
});

it('bypasses whitelisted ips', function () {
    config()->set('filament-loginguard.lockout.whitelist.ips', ['1.2.3.4']);

    for ($i = 0; $i < 50; $i++) {
        ($this->failed)();
    }

    expect(LoginAttempt::query()->count())->toBe(0);
});

it('bypasses whitelisted emails', function () {
    config()->set('filament-loginguard.lockout.whitelist.emails', ['A@EXAMPLE.com']);

    for ($i = 0; $i < 50; $i++) {
        ($this->failed)();
    }

    expect(LoginAttempt::query()->count())->toBe(0);
});

it('locks an ip when aggregate attempts across emails reach the threshold', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 3);

    ($this->failed)('a@example.com');
    ($this->failed)('b@example.com');
    ($this->failed)('c@example.com');

    $rows = LoginAttempt::query()->get();

    // One IP-scope lock covers all three rows.
    expect($rows)->toHaveCount(3)
        ->and(LoginGuardLock::query()->where('scope_type', LoginGuardLock::SCOPE_IP)->where('scope_key', '1.2.3.4')->where('locked_until', '>', now())->exists())->toBeTrue()
        ->and(LoginAttempt::query()->get()->every(fn (LoginAttempt $row): bool => app(LoginGuardService::class)->isLocked($row->ip, $row->email)))->toBeTrue();
});

it('locks an email when aggregate attempts across ips reach the threshold', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 3);

    foreach (['1.2.3.4', '5.6.7.8', '9.9.9.9'] as $ip) {
        request()->server->set('REMOTE_ADDR', $ip);
        ($this->failed)();
    }

    $rows = LoginAttempt::query()->get();

    // One email-scope lock covers all three rows.
    expect($rows)->toHaveCount(3)
        ->and(LoginGuardLock::query()->where('scope_type', LoginGuardLock::SCOPE_EMAIL)->where('scope_key', 'a@example.com')->where('locked_until', '>', now())->exists())->toBeTrue()
        ->and(LoginAttempt::query()->get()->every(fn (LoginAttempt $row): bool => app(LoginGuardService::class)->isLocked($row->ip, $row->email)))->toBeTrue();
});

it('treats an IPv4-mapped IPv6 address as the same key as its IPv4 form', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    request()->server->set('REMOTE_ADDR', '1.2.3.4');
    ($this->failed)();

    request()->server->set('REMOTE_ADDR', '::FFFF:1.2.3.4');
    ($this->failed)();

    expect(LoginAttempt::query()->count())->toBe(1)
        ->and(LoginAttempt::query()->sole()->ip)->toBe('1.2.3.4')
        ->and(app(LoginGuardService::class)->isLocked('1.2.3.4', 'a@example.com'))->toBeTrue();
});

it('tracks exact pairs only when both aggregates are off', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 3);
    config()->set('filament-loginguard.lockout.tracking.per_ip', false);
    config()->set('filament-loginguard.lockout.tracking.per_email', false);

    ($this->failed)('a@example.com');
    ($this->failed)('b@example.com');
    ($this->failed)('c@example.com');

    // One failure per pair: nothing reaches max_attempts, no locks exist.
    expect(LoginAttempt::query()->count())->toBe(3)
        ->and(LoginGuardLock::query()->count())->toBe(0);

    ($this->failed)('a@example.com');
    ($this->failed)('a@example.com');

    $service = app(LoginGuardService::class);

    expect($service->isLocked('1.2.3.4', 'a@example.com'))->toBeTrue()
        ->and($service->isLocked('1.2.3.4', 'b@example.com'))->toBeFalse();
});

it('honors each independent tracking toggle', function (bool $trackIp, bool $trackEmail, string $scope, string $key) {
    config()->set('filament-loginguard.lockout.max_attempts', 2);
    config()->set('filament-loginguard.lockout.tracking.per_ip', $trackIp);
    config()->set('filament-loginguard.lockout.tracking.per_email', $trackEmail);

    ($this->failed)();
    ($this->failed)();

    $lock = LoginGuardLock::query()->sole();
    $service = app(LoginGuardService::class);

    expect($lock->scope_type)->toBe($scope)
        ->and($lock->scope_key)->toBe($key)
        ->and($service->isLocked('1.2.3.4', 'unrelated@example.com'))->toBe($trackIp)
        ->and($service->isLocked('9.9.9.9', 'a@example.com'))->toBe($trackEmail);
})->with([
    'ip only' => [true, false, 'ip', '1.2.3.4'],
    'email only' => [false, true, 'email', 'a@example.com'],
]);

it('excludes failures exactly at the previous window cutoff', function (string $ip, string $email) {
    config()->set('filament-loginguard.lockout.max_attempts', 2);
    config()->set('filament-loginguard.lockout.attempts_window_minutes', 30);

    ($this->failed)();
    Carbon::setTestNow(now()->addMinutes(30));

    request()->server->set('REMOTE_ADDR', $ip);
    ($this->failed)($email);

    $row = LoginAttempt::query()->where('ip', $ip)->where('email', $email)->sole();

    expect($row->attempts)->toBe(1)
        ->and(LoginGuardLock::query()->count())->toBe(0);
})->with([
    'same pair' => ['1.2.3.4', 'a@example.com'],
    'same ip only' => ['1.2.3.4', 'b@example.com'],
    'same email only' => ['5.6.7.8', 'a@example.com'],
]);

it('stops blocking at the exact expiry of the furthest applicable lock', function () {
    $service = app(LoginGuardService::class);

    foreach (['ip' => ['1.2.3.4', 10], 'email' => ['a@example.com', 15]] as $scope => [$key, $minutes]) {
        LoginGuardLock::query()->create([
            'scope_type' => $scope,
            'scope_key' => $key,
            'locked_until' => now()->addMinutes($minutes),
            'escalation_count' => 1,
        ]);
    }

    Carbon::setTestNow(now()->addMinutes(15)->subSecond());

    expect($service->lockFor('1.2.3.4', 'a@example.com')?->toDateTimeString())->toBe('2026-01-01 00:15:00')
        ->and($service->remainingLockSeconds('1.2.3.4', 'a@example.com'))->toBe(1)
        ->and($service->isLocked('1.2.3.4', 'a@example.com'))->toBeTrue()
        ->and($service->isLocked('1.2.3.4', 'unrelated@example.com'))->toBeFalse();

    Carbon::setTestNow(now()->addSecond());

    expect($service->remainingLockSeconds('1.2.3.4', 'a@example.com'))->toBe(0)
        ->and($service->lockFor('1.2.3.4', 'a@example.com'))->toBeNull()
        ->and($service->isLocked('1.2.3.4', 'a@example.com'))->toBeFalse();
});

it('decays attempts outside the window', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 5);

    ($this->failed)();
    ($this->failed)();

    Carbon::setTestNow(now()->addMinutes(31));

    ($this->failed)();

    expect(LoginAttempt::query()->sole()->attempts)->toBe(1);
});

it('counts failures inside one fixed window, not across gap-less attempts', function () {
    // The window is a true fixed window: only failures that actually happened
    // inside the same window accumulate. A slow drip with 20-minute gaps (window
    // = 30 min) used to accumulate forever because `last_attempt_at` never aged
    // out; with `window_started_at` each window restarts at zero.
    config()->set('filament-loginguard.lockout.max_attempts', 10);
    config()->set('filament-loginguard.lockout.attempts_window_minutes', 30);

    // 6 failures, one every 20 minutes: each 30-minute window only ever holds
    // two of them, so the counter never climbs past 2 and no lockout happens.
    foreach ([20, 20, 20, 20, 20] as $gap) {
        ($this->failed)();
        Carbon::setTestNow(now()->addMinutes($gap));
    }
    ($this->failed)();

    expect(LoginAttempt::query()->sole()->attempts)->toBe(2)
        ->and(app(LoginGuardService::class)->isLocked('1.2.3.4', 'a@example.com'))->toBeFalse();
});

it('never accumulates beyond one window even after dozens of spaced failures', function () {
    // The old gap-reset semantics would reach max_attempts (10) after 10 slow
    // drips; the fixed window caps the counter at whatever fits in one window.
    config()->set('filament-loginguard.lockout.max_attempts', 10);
    config()->set('filament-loginguard.lockout.attempts_window_minutes', 30);

    for ($i = 0; $i < 12; $i++) {
        ($this->failed)();
        Carbon::setTestNow(now()->addMinutes(20));
    }

    expect((int) LoginAttempt::query()->sole()->attempts)->toBeLessThanOrEqual(2)
        ->and(app(LoginGuardService::class)->isLocked('1.2.3.4', 'a@example.com'))->toBeFalse();
});

it('locks out inside a single window when enough failures accumulate there', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 5);
    config()->set('filament-loginguard.lockout.attempts_window_minutes', 30);

    // 5 failures inside one 10-minute span — all in the same window.
    foreach ([1, 2, 3, 4] as $gap) {
        ($this->failed)();
        Carbon::setTestNow(now()->addMinutes($gap));
    }
    ($this->failed)();

    expect(app(LoginGuardService::class)->isLocked('1.2.3.4', 'a@example.com'))->toBeTrue();
});

it('records an escalation history entry for every applied lockout', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    ($this->failed)();
    ($this->failed)();

    // Both scopes triggered by this pair get a history entry.
    $ipHistory = LockoutHistory::query()->where('ip', '1.2.3.4')->sole();
    $emailHistory = LockoutHistory::query()->where('email', 'a@example.com')->sole();

    expect($ipHistory->ip)->toBe('1.2.3.4')
        ->and($ipHistory->email)->toBeNull()
        ->and($ipHistory->lockout_count)->toBe(1)
        ->and($ipHistory->duration_minutes)->toBe(15)
        ->and($ipHistory->locked_until->equalTo(now()->addMinutes(15)))->toBeTrue()
        ->and($emailHistory->email)->toBe('a@example.com')
        ->and($emailHistory->ip)->toBeNull()
        ->and($emailHistory->lockout_count)->toBe(1);
});

it('increments an existing attempt row through the failure service', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 4);

    $row = LoginAttempt::query()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'attempts' => 1,
        'window_started_at' => now(),
    ]);

    $service = app(LoginGuardService::class);
    $first = $service->recordFailure('1.2.3.4', 'a@example.com');
    $second = $service->recordFailure('1.2.3.4', 'a@example.com');

    expect($first->locked)->toBeFalse()
        ->and($second->locked)->toBeFalse()
        ->and($row->refresh()->attempts)->toBe(3)
        ->and(LoginAttempt::query()->count())->toBe(1);

    expect($service->recordFailure('1.2.3.4', 'a@example.com')->locked)->toBeTrue()
        ->and($row->refresh()->attempts)->toBe(4);
});

it('does not extend an active lock', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    ($this->failed)();
    ($this->failed)();

    $originalLockedUntil = LoginGuardLock::query()->where('scope_type', LoginGuardLock::SCOPE_IP)->where('scope_key', '1.2.3.4')->sole()->locked_until;

    Carbon::setTestNow(now()->addMinutes(5));

    ($this->failed)();

    // Attempts during an active lock are never counted (the listener skips
    // them), and the lock expiry does not move.
    expect(LoginAttempt::query()->sole()->attempts)->toBe(2)
        ->and(LoginGuardLock::query()->where('scope_type', LoginGuardLock::SCOPE_IP)->where('scope_key', '1.2.3.4')->sole()->locked_until->equalTo($originalLockedUntil))->toBeTrue();
});

it('releases only the successful account email lock and logs the release', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    ($this->failed)();
    ($this->failed)();

    request()->server->set('REMOTE_ADDR', '5.6.7.8');
    ($this->failed)('b@example.com');
    ($this->failed)('b@example.com');

    request()->server->set('REMOTE_ADDR', '1.2.3.4');
    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    $service = app(LoginGuardService::class);
    $row = LoginAttempt::query()->where('email', 'a@example.com')->sole();
    $release = SecurityEvent::query()->where('type', SecurityEvent::TYPE_UNLOCKED)->sole();

    expect($row->attempts)->toBe(0)
        ->and($row->last_attempt_at)->toBeNull()
        ->and($service->isLocked('9.9.9.9', 'a@example.com'))->toBeFalse()
        ->and($service->isLocked('1.2.3.4', 'unrelated@example.com'))->toBeTrue()
        ->and($service->isLocked('9.9.9.9', 'b@example.com'))->toBeTrue()
        ->and(Arr::sortRecursive($release->metadata ?? []))->toBe([
            'reason' => 'successful_login',
            'scope_key' => 'a@example.com',
            'scope_type' => 'email',
        ]);
});

it('starts a fresh failure window after successful login', function (?string $userEmail) {
    config()->set('filament-loginguard.lockout.max_attempts', 3);

    ($this->failed)();
    Carbon::setTestNow(now()->addMinutes(20));

    event(new Login('web', new TestUser(email: $userEmail), false));

    Carbon::setTestNow(now()->addMinutes(5));
    ($this->failed)();

    Carbon::setTestNow(now()->addMinutes(10));
    ($this->failed)();

    expect(LoginAttempt::query()->sole()->attempts)->toBe(2);
})->with([
    'user has an email' => ['a@example.com'],
    'user has no email' => [null],
]);

it('records successful logins on the attempts row', function () {
    ($this->failed)();

    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    $row = LoginAttempt::query()->sole();

    expect($row->success_count)->toBe(1)
        ->and($row->last_success_at->equalTo(now()))->toBeTrue()
        ->and($row->attempts)->toBe(0);
});

it('dispatches LoginLockedOut when a lockout is triggered', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    Event::fake([LoginLockedOut::class]);

    ($this->failed)();
    ($this->failed)();

    Event::assertDispatched(LoginLockedOut::class, fn (LoginLockedOut $event): bool => $event->ip === '1.2.3.4'
        && $event->email === 'a@example.com'
        && $event->lockedForMinutes === 15);
});

it('only resets the row of the account that logged in', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 5);

    ($this->failed)('a@example.com');
    ($this->failed)('a@example.com');
    ($this->failed)('b@example.com');
    ($this->failed)('b@example.com');
    ($this->failed)('b@example.com');

    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    $a = LoginAttempt::query()->where('email', 'a@example.com')->sole();
    $b = LoginAttempt::query()->where('email', 'b@example.com')->sole();

    expect($a->attempts)->toBe(0)
        ->and($a->last_attempt_at)->toBeNull()
        ->and($b->attempts)->toBe(3)
        ->and($b->last_attempt_at)->not->toBeNull();
});

it('respects the guards config', function () {
    config()->set('filament-loginguard.lockout.tracking.guards', ['web']);

    ($this->failed)('a@example.com', 'admin');

    expect(LoginAttempt::query()->count())->toBe(0);
});

it('does nothing when disabled', function () {
    config()->set('filament-loginguard.lockout.enabled', false);

    LoginGuardLock::query()->create([
        'scope_type' => 'email',
        'scope_key' => 'a@example.com',
        'locked_until' => now()->addMinutes(15),
        'escalation_count' => 1,
    ]);

    event(new Attempting('web', ['email' => 'a@example.com', 'password' => 'x'], false));

    for ($i = 0; $i < 20; $i++) {
        ($this->failed)();
    }

    expect(LoginAttempt::query()->count())->toBe(0)
        ->and(SecurityEvent::query()->where('type', SecurityEvent::TYPE_LOGIN_FAILED)->count())->toBe(0);
});

it('throws the lockout message when the threshold is crossed', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 1);

    try {
        event(new Failed('web', null, ['email' => 'a@example.com', 'password' => 'x']));
        $this->fail('Expected a ValidationException');
    } catch (ValidationException $exception) {
        expect($exception->errors()['data.email'][0])
            ->toBe('Too many failed login attempts. Access is blocked for 15 minutes. Please try again later.');
    }
});

it('normalizes email addresses', function () {
    ($this->failed)('  User@Example.COM ');

    expect(LoginAttempt::query()->sole()->email)->toBe('user@example.com');
});
