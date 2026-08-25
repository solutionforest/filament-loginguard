<?php

it('merges the config under the filament-loginguard key', function () {
    expect(config('filament-loginguard.lockout.enabled'))->toBeTrue()
        ->and(config('filament-loginguard.lockout.max_attempts'))->toBe(10)
        ->and(config('filament-loginguard.lockout.initial_minutes'))->toBe(15)
        ->and(config('filament-loginguard.lockout.escalation_hours'))->toBe([24, 72, 168])
        ->and(config('filament-loginguard.lockout.attempts_window_minutes'))->toBe(30)
        ->and(config('filament-loginguard.lockout.tracking.per_ip'))->toBeTrue()
        ->and(config('filament-loginguard.lockout.tracking.per_email'))->toBeTrue()
        ->and(config('filament-loginguard.lockout.tracking.guards'))->toBe([])
        ->and(config('filament-loginguard.lockout.whitelist.ips'))->toBe(['127.0.0.1', '::1'])
        ->and(config('filament-loginguard.lockout.whitelist.emails'))->toBe([])
        ->and(config('filament-loginguard.lockout.notifications.enabled'))->toBeTrue()
        ->and(config('filament-loginguard.lockout.notifications.mail.to'))->toBe([])
        ->and(config('filament-loginguard.lockout.notifications.mail.cooldown_minutes'))->toBe(60)
        ->and(config('filament-loginguard.lockout.notifications.mail.queue'))->toBeFalse()
        ->and(config('filament-loginguard.pages.attempts.enabled'))->toBeTrue()
        ->and(config('filament-loginguard.pages.attempts.slug'))->toBe('login-guard');
});
