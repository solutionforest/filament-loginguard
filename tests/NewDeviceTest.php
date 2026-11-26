<?php

use Carbon\Carbon;
use Illuminate\Auth\Events\Login;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use SolutionForest\FilamentLoginGuard\Models\KnownDevice;
use SolutionForest\FilamentLoginGuard\Models\UserSession;
use SolutionForest\FilamentLoginGuard\Notifications\NewDeviceLoginNotification;
use SolutionForest\FilamentLoginGuard\Support\DeviceCookie;
use SolutionForest\FilamentLoginGuard\Tests\Support\TestUser;

beforeEach(function () {
    Carbon::setTestNow('2026-01-01 00:00:00');

    request()->server->set('REMOTE_ADDR', '1.2.3.4');
    request()->headers->set('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36');
});

afterEach(function () {
    Carbon::setTestNow(null);
});

it('records a device fingerprint on login', function () {
    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    expect(KnownDevice::query()
        ->where('user_id', 1)
        ->where('fingerprint', 'Chrome on macOS')
        ->exists())->toBeTrue();
});

it('notifies the account owner only the first time a device is seen', function () {
    config()->set('filament-loginguard.sessions.new_device.notifications.enabled', true);

    Notification::fake();

    event(new Login('web', new TestUser(email: 'a@example.com'), false));
    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    Notification::assertSentOnDemandTimes(NewDeviceLoginNotification::class, 1);

    Notification::assertSentOnDemand(
        NewDeviceLoginNotification::class,
        fn (NewDeviceLoginNotification $notification, array $channels, object $notifiable): bool => $notifiable->routes['mail'] === 'a@example.com'
    );
});

it('does not notify when the account has no email', function () {
    config()->set('filament-loginguard.sessions.new_device.notifications.enabled', true);

    Notification::fake();

    event(new Login('web', new TestUser(email: null), false));

    Notification::assertNothingSent();
});

it('does not record a device when the user agent cannot be parsed', function () {
    request()->headers->set('User-Agent', 'test');

    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    expect(KnownDevice::query()->count())->toBe(0);
});

it('does not record devices when new-device tracking is disabled', function () {
    config()->set('filament-loginguard.sessions.new_device.enabled', false);

    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    expect(KnownDevice::query()->count())->toBe(0);
});

it('queues the new-device notification when a queue is configured', function () {
    config()->set('filament-loginguard.sessions.new_device.notifications.enabled', true);
    config()->set('filament-loginguard.sessions.new_device.notifications.mail.queue', 'notifications');

    Queue::fake();

    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    Queue::assertPushedOn(
        'notifications',
        SendQueuedNotifications::class,
        fn (SendQueuedNotifications $job): bool => $job->notification instanceof NewDeviceLoginNotification
    );
});

it('sends the new-device notification synchronously by default', function () {
    config()->set('filament-loginguard.sessions.new_device.notifications.enabled', true);

    Notification::fake();

    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    Notification::assertSentOnDemandTimes(NewDeviceLoginNotification::class, 1);
});

it('flags sessions whose device fingerprint is new', function () {
    KnownDevice::query()->create([
        'user_id' => 42,
        'fingerprint' => 'Chrome on macOS',
        'first_seen_at' => now()->subHour(),
    ]);

    $session = UserSession::query()->create([
        'id' => 'new-device-session',
        'user_id' => 42,
        'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    expect($session->is_new_device)->toBeTrue();

    KnownDevice::query()->where('user_id', 42)->update(['first_seen_at' => now()->subHours(48)]);

    expect($session->refresh()->is_new_device)->toBeFalse();
});

it('notifies once per new cookie identity even when browser fingerprints match', function (bool $legacyEnabled) {
    Notification::fake();
    config()->set('filament-loginguard.devices.notifications.new_device', true);
    config()->set('filament-loginguard.sessions.new_device.notifications.enabled', $legacyEnabled);
    $user = new TestUser(email: 'owner@example.com');

    event(new Login('web', $user, false));
    $name = DeviceCookie::name();
    request()->cookies->set($name, Cookie::queued($name)->getValue());
    event(new Login('web', $user, false));

    Notification::assertSentOnDemandTimes(NewDeviceLoginNotification::class, 1);

    request()->cookies->remove($name);
    event(new Login('web', $user, false));

    Notification::assertSentOnDemandTimes(NewDeviceLoginNotification::class, 2);
    Notification::assertSentOnDemand(
        NewDeviceLoginNotification::class,
        fn (NewDeviceLoginNotification $message, array $channels, object $recipient): bool => $recipient->routes['mail'] === 'owner@example.com'
            && $message->ip === '1.2.3.4' && $message->device === 'Chrome on macOS',
    );
    expect(KnownDevice::query()->count())->toBe(1);
})->with([false, true]);

it('queues an identity notification on its own queue', function () {
    Queue::fake();
    config()->set('filament-loginguard.sessions.enabled', false);
    config()->set('filament-loginguard.devices.notifications.new_device', true);
    config()->set('filament-loginguard.devices.notifications.mail.queue', 'device-alerts');

    event(new Login('web', new TestUser(email: 'owner@example.com'), false));

    Queue::assertPushedOn(
        'device-alerts',
        SendQueuedNotifications::class,
        fn (SendQueuedNotifications $job): bool => $job->notification instanceof NewDeviceLoginNotification
    );
});

it('skips cookie identity notifications for disabled features or missing recipients', function (bool $enabled, bool $notify, ?string $email) {
    Notification::fake();
    config()->set('filament-loginguard.devices.enabled', $enabled);
    config()->set('filament-loginguard.devices.notifications.new_device', $notify);

    event(new Login('web', new TestUser(email: $email), false));

    Notification::assertNothingSent();
})->with([[true, false, 'owner@example.com'], [false, true, 'owner@example.com'], [true, true, null]]);
