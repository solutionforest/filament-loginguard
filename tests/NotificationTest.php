<?php

use Carbon\Carbon;
use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Facades\Notification;
use Illuminate\Validation\ValidationException;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Notifications\AccountLockedNotification;

beforeEach(function () {
    Carbon::setTestNow('2026-01-01 00:00:00');
    request()->server->set('REMOTE_ADDR', '1.2.3.4');
    config()->set('filament-loginguard.lockout.whitelist.ips', []);
    config()->set('filament-loginguard.lockout.max_attempts', 2);
    config()->set('filament-loginguard.lockout.notifications.enabled', true);
    config()->set('filament-loginguard.lockout.notifications.mail.to', ['admin@example.com']);

    // Dispatch a Failed event, swallowing the ValidationException that lockout-triggering
    // attempts throw by design.
    $this->failed = function (): void {
        try {
            event(new Failed('web', null, ['email' => 'a@example.com', 'password' => 'x']));
        } catch (ValidationException) {
            // Expected when this attempt crosses the lockout threshold.
        }
    };
});

afterEach(function () {
    Carbon::setTestNow(null);
});

it('notifies recipients when a lockout is triggered', function () {
    Notification::fake();

    ($this->failed)();
    ($this->failed)();

    Notification::assertSentOnDemand(
        AccountLockedNotification::class,
        fn (AccountLockedNotification $notification, array $channels, object $notifiable): bool => $notification->ip === '1.2.3.4'
            && $notification->email === 'a@example.com'
            && $notification->minutes === 15
    );
});

it('sends nothing when no recipients are configured', function () {
    Notification::fake();
    config()->set('filament-loginguard.lockout.notifications.mail.to', []);

    ($this->failed)();
    ($this->failed)();

    Notification::assertNothingSent();
});

it('throttles notifications per ip within the cooldown window', function () {
    Notification::fake();
    config()->set('filament-loginguard.lockout.notifications.mail.cooldown_minutes', 60);

    // First lockout.
    ($this->failed)();
    ($this->failed)();

    // Wait out the lock, then trigger a second lockout (still inside the cooldown window).
    Carbon::setTestNow(now()->addMinutes(16));

    LoginAttempt::query()->delete();

    ($this->failed)();
    ($this->failed)();

    Notification::assertSentOnDemandTimes(AccountLockedNotification::class, 1);
});

it('sends again after the cooldown expires', function () {
    Notification::fake();
    config()->set('filament-loginguard.lockout.notifications.mail.cooldown_minutes', 60);

    ($this->failed)();
    ($this->failed)();

    Carbon::setTestNow(now()->addMinutes(61));

    LoginAttempt::query()->delete();

    ($this->failed)();
    ($this->failed)();

    Notification::assertSentOnDemandTimes(AccountLockedNotification::class, 2);
});
