<?php

it('merges the config under the filament-loginguard key', function () {
    expect(config('filament-loginguard.enabled'))->toBeTrue()
        ->and(config('filament-loginguard.max_attempts'))->toBe(10)
        ->and(config('filament-loginguard.lockout_minutes'))->toBe(15)
        ->and(config('filament-loginguard.ban_hours'))->toBe([24, 72, 168])
        ->and(config('filament-loginguard.attempts_window_minutes'))->toBe(30)
        ->and(config('filament-loginguard.tracking.per_ip'))->toBeTrue()
        ->and(config('filament-loginguard.tracking.per_email'))->toBeTrue()
        ->and(config('filament-loginguard.tracking.guards'))->toBe([])
        ->and(config('filament-loginguard.whitelisted_ips'))->toBe(['127.0.0.1', '::1'])
        ->and(config('filament-loginguard.whitelisted_emails'))->toBe([])
        ->and(config('filament-loginguard.notifications.enabled'))->toBeTrue()
        ->and(config('filament-loginguard.notifications.mail.to'))->toBe([])
        ->and(config('filament-loginguard.notifications.mail.cooldown_minutes'))->toBe(60)
        ->and(config('filament-loginguard.notifications.mail.queue'))->toBeFalse()
        ->and(config('filament-loginguard.attempts.page.enabled'))->toBeTrue()
        ->and(config('filament-loginguard.attempts.page.slug'))->toBe('login-guard');
});
