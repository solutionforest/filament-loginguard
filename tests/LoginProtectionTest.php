<?php

use Carbon\Carbon;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Event;
use Illuminate\Validation\ValidationException;
use SolutionForest\FilamentLoginGuard\Events\LoginLockedOut;
use SolutionForest\FilamentLoginGuard\LoginGuardService;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
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

it('locks out when the max attempts are reached', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 3);

    ($this->failed)();
    ($this->failed)();

    expect(LoginAttempt::query()->sole()->isLocked())->toBeFalse();

    ($this->failed)();

    $row = LoginAttempt::query()->sole();

    expect($row->isLocked())->toBeTrue()
        ->and($row->lockout_count)->toBe(1)
        ->and($row->locked_until->equalTo(now()->addMinutes(15)))->toBeTrue();
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

    expect(LoginAttempt::query()->sole()->lockout_count)->toBe(1);

    // Second lockout: 24 hours.
    Carbon::setTestNow(now()->addMinutes(16));

    for ($i = 0; $i < 3; $i++) {
        ($this->failed)();
    }

    $row = LoginAttempt::query()->sole();

    expect($row->lockout_count)->toBe(2)
        ->and($row->locked_until->equalTo(now()->addHours(24)))->toBeTrue();

    // Third lockout: 72 hours.
    Carbon::setTestNow(now()->addDay()->addMinutes(1));

    for ($i = 0; $i < 3; $i++) {
        ($this->failed)();
    }

    $row = LoginAttempt::query()->sole();

    expect($row->lockout_count)->toBe(3)
        ->and($row->locked_until->equalTo(now()->addHours(72)))->toBeTrue();
});

it('computes escalation durations and caps at the last ban', function () {
    $service = app(LoginGuardService::class);

    expect($service->durationForLockoutCount(1))->toBe(15)
        ->and($service->durationForLockoutCount(2))->toBe(24 * 60)
        ->and($service->durationForLockoutCount(3))->toBe(72 * 60)
        ->and($service->durationForLockoutCount(4))->toBe(168 * 60)
        ->and($service->durationForLockoutCount(9))->toBe(168 * 60);

    config()->set('filament-loginguard.lockout.ban_hours', []);

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

    expect($rows)->toHaveCount(3)
        ->and($rows->every(fn (LoginAttempt $row): bool => $row->isLocked()))->toBeTrue();
});

it('locks an email when aggregate attempts across ips reach the threshold', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 3);

    foreach (['1.2.3.4', '5.6.7.8', '9.9.9.9'] as $ip) {
        request()->server->set('REMOTE_ADDR', $ip);
        ($this->failed)();
    }

    $rows = LoginAttempt::query()->get();

    expect($rows)->toHaveCount(3)
        ->and($rows->every(fn (LoginAttempt $row): bool => $row->isLocked()))->toBeTrue();
});

it('tracks exact pairs only when both aggregates are off', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 3);
    config()->set('filament-loginguard.lockout.tracking.per_ip', false);
    config()->set('filament-loginguard.lockout.tracking.per_email', false);

    ($this->failed)('a@example.com');
    ($this->failed)('b@example.com');
    ($this->failed)('c@example.com');

    expect(LoginAttempt::query()->where('locked_until', '>', now())->count())->toBe(0);

    ($this->failed)('a@example.com');
    ($this->failed)('a@example.com');

    $a = LoginAttempt::query()->where('email', 'a@example.com')->sole();
    $b = LoginAttempt::query()->where('email', 'b@example.com')->sole();

    expect($a->isLocked())->toBeTrue()
        ->and($b->isLocked())->toBeFalse();
});

it('decays attempts outside the window', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 5);

    ($this->failed)();
    ($this->failed)();

    Carbon::setTestNow(now()->addMinutes(31));

    ($this->failed)();

    expect(LoginAttempt::query()->sole()->attempts)->toBe(1);
});

it('does not extend an active lock', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    ($this->failed)();
    ($this->failed)();

    $originalLockedUntil = LoginAttempt::query()->sole()->locked_until;

    Carbon::setTestNow(now()->addMinutes(5));

    ($this->failed)();

    $row = LoginAttempt::query()->sole();

    expect($row->attempts)->toBe(2)
        ->and($row->locked_until->equalTo($originalLockedUntil))->toBeTrue();
});

it('resets counters on successful login', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    ($this->failed)();
    ($this->failed)();

    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    $row = LoginAttempt::query()->sole();

    expect($row->attempts)->toBe(0)
        ->and($row->lockout_count)->toBe(0)
        ->and($row->locked_until)->toBeNull()
        ->and($row->last_attempt_at)->toBeNull();
});

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

    for ($i = 0; $i < 20; $i++) {
        ($this->failed)();
    }

    expect(LoginAttempt::query()->count())->toBe(0);

    // No exception should be thrown either.
    event(new Attempting('web', ['email' => 'a@example.com', 'password' => 'x'], false));

    expect(true)->toBeTrue();
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
