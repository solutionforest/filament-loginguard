<?php

// config for SolutionForest/FilamentLoginGuard
return [

    // Master switch. When false, no attempt is recorded and no lockout is enforced.
    'enabled' => true,

    // Number of failed login attempts allowed inside `attempts_window_minutes` before a lockout.
    'max_attempts' => 10,

    // Duration of the FIRST lockout, in minutes.
    'lockout_minutes' => 15,

    // Escalating lockout durations for the 2nd, 3rd, ... lockout, in HOURS.
    // With [24, 72, 168]: 2nd lockout = 1 day, 3rd = 3 days, 4th+ = 7 days.
    // The last value is reused for every subsequent lockout. Empty array = always `lockout_minutes`.
    'ban_hours' => [24, 72, 168],

    // (a) attempts older than this window are not counted (attempt counter decays back to 0),
    // (b) this is also the window used for the aggregate per-IP / per-email sums.
    'attempts_window_minutes' => 30,

    'tracking' => [
        // Lock out an IP when the SUM of attempts across all emails used from it reaches `max_attempts`.
        'per_ip' => true,
        // Lock out an email when the SUM of attempts across all IPs used for it reaches `max_attempts`.
        'per_email' => true,
        // Restrict tracking to specific auth guards (e.g. ['web']). Empty array = track all guards.
        'guards' => [],
    ],

    // These never get recorded and are never locked out. Localhost is whitelisted by default.
    'whitelisted_ips' => [
        '127.0.0.1',
        '::1',
    ],

    // Emails that can always log in, even when they would be locked out.
    'whitelisted_emails' => [],

    'notifications' => [
        'enabled' => true,
        'mail' => [
            // Admin addresses to notify when a lockout is triggered. Empty array = no notifications.
            'to' => [],
            // At most one notification per IP within this window (cache-backed throttle).
            'cooldown_minutes' => 60,
            // Queue name to send on, or false to send synchronously.
            'queue' => false,
        ],
    ],

    'admin_page' => [
        'enabled' => true,
        'slug' => 'login-guard',
        // Optional class-string of a Filament Cluster (e.g. App\Filament\Clusters\Settings\SettingsCluster)
        // to nest the page under. null = top-level navigation item.
        'cluster' => null,
        // Labels fall back to translations when null.
        'navigation_label' => null,
        'navigation_icon' => 'heroicon-o-shield-exclamation',
        'navigation_group' => null,
        'navigation_sort' => null,
        // Optional ability name (string) that the logged-in user must pass via `$user->can(...)`
        // to view the page. null = any authenticated panel user. Fail-closed when the ability
        // is not registered anywhere.
        'authorize' => null,
    ],
];
