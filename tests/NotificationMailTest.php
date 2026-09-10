<?php

use Illuminate\Notifications\AnonymousNotifiable;
use SolutionForest\FilamentLoginGuard\Notifications\AccountLockedNotification;
use SolutionForest\FilamentLoginGuard\Notifications\NewDeviceLoginNotification;

it('renders the lockout email with the lock details', function () {
    $notification = new AccountLockedNotification(ip: '1.2.3.4', email: 'a@example.com', minutes: 15);

    $mail = $notification->toMail(new AnonymousNotifiable);

    expect($notification->via(new AnonymousNotifiable))->toBe(['mail'])
        ->and($mail->subject)->toBe('LoginGuard lockout triggered')
        ->and($mail->greeting)->toBe('A login lockout has been triggered.')
        ->and($mail->introLines)->toBe([
            'IP address: 1.2.3.4',
            'Email: a@example.com',
            'Blocked for 15 minutes.',
        ]);
});

it('includes the self-unlock action when an unlock url is provided', function () {
    $notification = new AccountLockedNotification(ip: '1.2.3.4', email: 'a@example.com', minutes: 15, unlockUrl: 'https://example.com/unlock');

    $mail = $notification->toMail(new AnonymousNotifiable);

    expect($mail->actionText)->toBe('Unlock my email')
        ->and($mail->actionUrl)->toBe('https://example.com/unlock');
});

it('has no action when no unlock url is provided', function () {
    $notification = new AccountLockedNotification(ip: '1.2.3.4', email: 'a@example.com', minutes: 15);

    $mail = $notification->toMail(new AnonymousNotifiable);

    expect($mail->actionText)->toBeNull()
        ->and($mail->actionUrl)->toBeNull();
});

it('renders the new-device email with the device details', function () {
    $notification = new NewDeviceLoginNotification(email: 'a@example.com', device: 'Chrome on macOS', ip: '1.2.3.4');

    $mail = $notification->toMail(new AnonymousNotifiable);

    expect($notification->via(new AnonymousNotifiable))->toBe(['mail'])
        ->and($mail->subject)->toBe('New device login detected')
        ->and($mail->greeting)->toBe('A login from a new device has been detected.')
        ->and($mail->introLines)->toBe([
            'User: a@example.com',
            'Device: Chrome on macOS',
            'IP address: 1.2.3.4',
        ]);
});
