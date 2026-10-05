<?php

use Carbon\Carbon;
use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\URL;
use Illuminate\Validation\ValidationException;
use SolutionForest\FilamentLoginGuard\LoginGuardService;
use SolutionForest\FilamentLoginGuard\Models\LockoutHistory;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Models\LoginGuardLock;
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

        expect(isLockedFor('1.2.3.4', 'a@example.com'))->toBeTrue('the lockout should be active before unlocking');
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

function isLockedFor(string $ip, string $email): bool
{
    return app(LoginGuardService::class)->isLocked($ip, $email);
}

/**
 * GET the confirmation page, then POST it (the state change only happens on POST).
 */
function confirmUnlock(string $url)
{
    test()->get($url)->assertOk()->assertSee('Unlock my email');

    return test()->post($url);
}

it('sends the unlock link to the blocked address, independent of admin recipients', function () {
    Notification::fake();
    config()->set('filament-loginguard.lockout.notifications.mail.to', []);

    ($this->lock)();

    // The self-unlock email must still go out, addressed to the victim.
    Notification::assertSentOnDemand(
        AccountLockedNotification::class,
        function (AccountLockedNotification $notification, array $channels, object $notifiable): bool {
            expect($notifiable->routes['mail'])->toBe('a@example.com')
                ->and($notification->unlockUrl)->toBeString()
                ->and(str_contains((string) $notification->unlockUrl, 'a@example.com'))->toBeFalse('the email must never appear in the URL');

            $path = parse_url((string) $notification->unlockUrl, PHP_URL_PATH);

            expect(is_string($path) && str_starts_with($path, '/filament-loginguard/unlock/'))->toBeTrue();

            return true;
        }
    );
});

it('still notifies admins when self-unlock is disabled', function () {
    Notification::fake();
    config()->set('filament-loginguard.lockout.notifications.self_unlock.enabled', false);

    ($this->lock)();

    Notification::assertSentOnDemand(
        AccountLockedNotification::class,
        fn (AccountLockedNotification $notification): bool => $notification->unlockUrl === null
    );
});

it('unlocks the email via the confirmation flow without touching other rows', function () {
    ($this->lock)();

    // A second, unrelated locked row (another IP + another email, e.g. the attacker's own lock).
    $attacker = LoginAttempt::factory()->locked(lockedUntil: now()->addMinutes(15))->create();

    $url = app(LoginGuardService::class)->selfUnlockUrl('a@example.com');

    // GET only shows the confirmation page — mail scanners are harmless.
    $this->get($url)->assertOk()->assertSee('Unlock my email');
    expect(isLockedFor('1.2.3.4', 'a@example.com'))->toBeTrue();

    $this->post($url)
        ->assertOk()
        ->assertSee('Your email has been unlocked');

    // The EMAIL lock is released; the IP lock from the same attack survives,
    // and attempt counters/escalation history are kept.
    expect(LoginGuardLock::query()->where('scope_type', 'email')->where('scope_key', 'a@example.com')->exists())->toBeFalse()
        ->and(LoginGuardLock::query()->where('scope_type', 'ip')->where('scope_key', '1.2.3.4')->exists())->toBeTrue()
        ->and(isLockedFor('1.2.3.4', 'a@example.com'))->toBeTrue('the IP lock still blocks the pair')
        ->and(victimRow()->attempts)->toBe(2);

    // The attacker's lock is untouched.
    expect(isLockedFor($attacker->ip, $attacker->email))->toBeTrue();

    // An append-only history row was recorded.
    expect(LockoutHistory::query()->where('email', 'a@example.com')->count())->toBe(1);
});

it('releasing the email lock still leaves the ip lock active', function () {
    // The scenario the scoped lock model exists for: the victim's email lock
    // was part of the same attack that locked the IP. Self-unlock must not
    // hand the attacker back their IP.
    ($this->lock)();

    $url = app(LoginGuardService::class)->selfUnlockUrl('a@example.com');

    $this->post($url)->assertOk();

    $service = app(LoginGuardService::class);

    expect(LoginGuardLock::query()->where('scope_type', 'email')->where('scope_key', 'a@example.com')->exists())->toBeFalse()
        ->and(LoginGuardLock::query()->where('scope_type', 'ip')->where('scope_key', '1.2.3.4')->where('locked_until', '>', now())->exists())->toBeTrue()
        ->and($service->isLocked('1.2.3.4', 'someone-else@example.com'))->toBeTrue('the IP lock protects every other account too');
});

it('unlocks when following the real rendered form flow', function () {
    // Simulate exactly what a mailbox owner does: GET the signed URL, parse the
    // confirmation form's action attribute, then POST to it. The action must
    // carry the signature/expires query string, otherwise the POST would 403.
    ($this->lock)();

    $url = app(LoginGuardService::class)->selfUnlockUrl('a@example.com');

    $confirmHtml = $this->get($url)
        ->assertOk()
        ->assertSee('Unlock my email')
        ->getContent();

    preg_match('/<form method="POST" action="([^"]+)"/', $confirmHtml, $matches);

    expect($matches[1] ?? null)->toBeString();

    $formAction = html_entity_decode($matches[1]);

    // The form action must include the signed URL's query string.
    expect(str_contains($formAction, 'signature='))->toBeTrue();

    $this->post($formAction)
        ->assertOk()
        ->assertSee('Your email has been unlocked');

    expect(LoginGuardLock::query()->where('scope_type', 'email')->where('scope_key', 'a@example.com')->exists())->toBeFalse();
});

it('rejects a tampered link', function () {
    ($this->lock)();

    $url = app(LoginGuardService::class)->selfUnlockUrl('a@example.com');

    // The token is a path segment; swap it for a different one. The signature
    // (which covers the token) no longer matches, so the link must be rejected.
    $tampered = (string) str_replace('/unlock/', '/unlock/tampered', $url);

    expect($tampered)->not->toBe($url);

    $this->get($tampered)->assertForbidden();
    $this->post($tampered)->assertForbidden();

    expect(isLockedFor('1.2.3.4', 'a@example.com'))->toBeTrue();
});

it('rejects an expired link', function () {
    ($this->lock)();

    $url = app(LoginGuardService::class)->selfUnlockUrl('a@example.com');

    Carbon::setTestNow(now()->addMinutes(61));

    $this->get($url)->assertForbidden();
    $this->post($url)->assertForbidden();

    // The lock also expired naturally; the point is that the link did not
    // unlock anything — verified by the 403s above.
    expect(true)->toBeTrue();
});

it('rejects a replayed link', function () {
    ($this->lock)();

    $url = app(LoginGuardService::class)->selfUnlockUrl('a@example.com');

    $this->post($url)->assertOk();

    expect(LoginGuardLock::query()->where('scope_type', 'email')->where('scope_key', 'a@example.com')->exists())->toBeFalse();

    // Restore the attack context, wait out the still-active IP lock (attempts
    // during an active lock are not recorded), then re-lock the email and
    // replay the consumed link.
    ($this->setAttackIp)();

    Carbon::setTestNow(now()->addMinutes(16));

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

    expect(LoginGuardLock::query()->where('scope_type', 'email')->where('scope_key', 'a@example.com')->where('locked_until', '>', now())->exists())->toBeTrue();

    $this->post($url)->assertOk()->assertSee('already been used');

    expect(LoginGuardLock::query()->where('scope_type', 'email')->where('scope_key', 'a@example.com')->where('locked_until', '>', now())->exists())->toBeTrue();
});

it('keeps the escalation ladder after a self-unlock', function () {
    ($this->lock)();

    $url = app(LoginGuardService::class)->selfUnlockUrl('a@example.com');

    $this->post($url)->assertOk();

    // Restore the attack context and re-trigger the lockout after every lock
    // has expired (the IP lock still blocks until 15 minutes pass — attempts
    // during an active lock are not even recorded). The email scope's
    // escalation position comes from its history (1 entry), so the next email
    // lock must be the 2nd step (24h), not 15 minutes.
    ($this->setAttackIp)();

    Carbon::setTestNow(now()->addMinutes(16));

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

    expect(LoginGuardLock::query()->where('scope_type', LoginGuardLock::SCOPE_EMAIL)->where('scope_key', 'a@example.com')->sole()->locked_until->equalTo(now()->addDay()))->toBeTrue()
        ->and($row->attempts)->toBe(3);
});

it('reports no active lock when the email is not locked', function () {
    $url = app(LoginGuardService::class)->selfUnlockUrl('not-locked@example.com');

    $this->post($url)->assertOk()->assertSee('no active lock');
});

it('returns zero rows unlocked for a blank email', function () {
    expect(app(LoginGuardService::class)->unlockEmail('   '))->toBe(0);
});

it('does not generate the route when it is missing', function () {
    // Simulate an app without the route: URL facade throws for unknown routes.
    URL::shouldReceive('temporarySignedRoute')->andThrow(new RuntimeException('route missing'));

    expect(app(LoginGuardService::class)->selfUnlockUrl('a@example.com'))->toBeNull();
});
