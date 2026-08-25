<?php

use Carbon\Carbon;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Notification;
use SolutionForest\FilamentLoginGuard\Models\KnownDevice;
use SolutionForest\FilamentLoginGuard\Models\UserSession;
use SolutionForest\FilamentLoginGuard\Notifications\NewDeviceLoginNotification;
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

it('notifies only the first time a device is seen', function () {
    config()->set('filament-loginguard.sessions.new_device.notifications.enabled', true);
    config()->set('filament-loginguard.sessions.new_device.notifications.mail.to', ['security@example.com']);

    Notification::fake();

    event(new Login('web', new TestUser(email: 'a@example.com'), false));
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
