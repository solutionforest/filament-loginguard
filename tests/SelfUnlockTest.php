<?php

use Carbon\Carbon;
use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\URL;
use Illuminate\Validation\ValidationException;
use SolutionForest\FilamentLoginGuard\LoginGuardService;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Notifications\AccountLockedNotification;

beforeEach(function () {
    Carbon::setTestNow('2026-01-01 00:00:00');
    config()->set('filament-loginguard.lockout.whitelist.ips', []);
    config()->set('filament-loginguard.lockout.max_attempts', 2);
    config()->set('filament-loginguard.lockout.notifications.enabled', true);
    config()->set('filament-loginguard.lockout.notifications.mail.to', ['admin@example.com']);
    config()->set('filament-loginguard.lockout.notifications.self_unlock.enabled', true);

    $this->setAttackIp = function (): void {
        request()->server->set('REMOTE_ADDR', '1.2.3.4');
        request()->headers->remove('X-Forwarded-For');
    };

    ($this->setAttackIp)();

    // Dispatch a Failed event, swallowing the ValidationException that
    // lockout-triggering attempts throw by design.
    $this->failed = function (): void {
        try {
            event(new Failed('web', null, ['email' => 'a@example.com', 'password' => 'x']));
        } catch (ValidationException) {
            // Expected when this attempt crosses the lockout threshold.
        }
    };

    $this->lock = function (): void {
        ($this->failed)();
        ($this->failed)();

        expect(victimRow()->isLocked())->toBeTrue('the lockout should be active before unlocking');
    };
});

afterEach(function () {
    Carbon::setTestNow(null);
});

/** The victim's attempt row, keyed on the attacking IP + email. */
function victimRow(): LoginAttempt
{
    return LoginAttempt::query()->where('ip', '1.2.3.4')->where('email', 'a@example.com')->sole();
}

it('appends a signed unlock link to the lockout notification', function () {
    Notification::fake();

    ($this->lock)();

    Notification::assertSentOnDemand(
        AccountLockedNotification::class,
        function (AccountLockedNotification $notification): bool {
            expect($notification->unlockUrl)->toBeString();

            $path = parse_url((string) $notification->unlockUrl, PHP_URL_PATH);

            expect($path)->toBe('/filament-loginguard/unlock/a@example.com');

            return true;
        }
    );
});

it('omits the unlock link when self-unlock is disabled', function () {
    Notification::fake();
    config()->set('filament-loginguard.lockout.notifications.self_unlock.enabled', false);

    ($this->lock)();

    Notification::assertSentOnDemand(
        AccountLockedNotification::class,
        fn (AccountLockedNotification $notification): bool => $notification->unlockUrl === null
    );
});

it('unlocks the email via the signed link without touching other rows', function () {
    ($this->lock)();

    // A second, unrelated locked row (another IP + another email, e.g. the attacker's own lock).
    $attacker = LoginAttempt::factory()->locked()->create(['ip' => '5.6.7.8', 'email' => 'attacker@example.com']);

    $url = app(LoginGuardService::class)->selfUnlockUrl('a@example.com');

    $this->get($url)
        ->assertOk()
        ->assertSee('Your email has been unlocked');

    // Email lock is gone, attempts/lockout history kept.
    $row = victimRow();
    expect($row->locked_until)->toBeNull()
        ->and($row->lockout_count)->toBe(1)
        ->and($row->attempts)->toBe(2);

    // The attacker's lock is untouched.
    expect($attacker->refresh()->isLocked())->toBeTrue();
});

it('rejects a tampered link', function () {
    ($this->lock)();

    $url = app(LoginGuardService::class)->selfUnlockUrl('a@example.com');
    $tampered = str_replace('/unlock/a@example.com', '/unlock/victim@example.com', $url);

    $this->get($tampered)->assertForbidden();

    expect(victimRow()->isLocked())->toBeTrue();
});

it('rejects an expired link', function () {
    ($this->lock)();

    $url = app(LoginGuardService::class)->selfUnlockUrl('a@example.com');

    Carbon::setTestNow(now()->addMinutes(61));

    $this->get($url)->assertForbidden();

    expect(victimRow()->locked_until)->not->toBeNull();
});

it('rejects a replayed link', function () {
    ($this->lock)();

    $url = app(LoginGuardService::class)->selfUnlockUrl('a@example.com');

    $this->get($url)->assertOk();

    expect(victimRow()->isLocked())->toBeFalse();

    // Restore the attack context (the GET request replaced the request instance)
    // and re-lock the email, then replay the consumed link.
    ($this->setAttackIp)();

    try {
        event(new Failed('web', null, ['email' => 'a@example.com', 'password' => 'x']));
    } catch (ValidationException) {
        //
    }

    try {
        event(new Failed('web', null, ['email' => 'a@example.com', 'password' => 'x']));
    } catch (ValidationException) {
        //
    }

    expect(victimRow()->refresh()->isLocked())->toBeTrue();

    $this->get($url)->assertOk()->assertSee('already been used');

    expect(victimRow()->refresh()->isLocked())->toBeTrue();
});

it('keeps the escalation ladder after a self-unlock', function () {
    ($this->lock)();

    $url = app(LoginGuardService::class)->selfUnlockUrl('a@example.com');

    $this->get($url)->assertOk();

    // Restore the attack context and re-trigger the lockout: lockout_count is 1,
    // so the next lock must be the 2nd escalation step (24h), not 15 minutes.
    ($this->setAttackIp)();

    try {
        event(new Failed('web', null, ['email' => 'a@example.com', 'password' => 'x']));
    } catch (ValidationException) {
        //
    }

    try {
        event(new Failed('web', null, ['email' => 'a@example.com', 'password' => 'x']));
    } catch (ValidationException) {
        //
    }

    $row = victimRow();

    expect($row->lockout_count)->toBe(2)
        ->and($row->locked_until->equalTo(now()->addDay()))->toBeTrue();
});

it('reports no active lock when the email is not locked', function () {
    $url = app(LoginGuardService::class)->selfUnlockUrl('not-locked@example.com');

    $this->get($url)->assertOk()->assertSee('no active lock');
});

it('returns zero rows unlocked for a blank email', function () {
    expect(app(LoginGuardService::class)->unlockEmail('   '))->toBe(0);
});

it('does not generate the route when it is missing', function () {
    // Simulate an app without the route: URL facade throws for unknown routes.
    URL::shouldReceive('temporarySignedRoute')->andThrow(new RuntimeException('route missing'));

    expect(app(LoginGuardService::class)->selfUnlockUrl('a@example.com'))->toBeNull();
});
