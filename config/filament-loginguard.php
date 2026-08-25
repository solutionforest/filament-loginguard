<?php

// config for SolutionForest/FilamentLoginGuard
return [

    /*
    |--------------------------------------------------------------------------
    | Lockout / brute-force protection
    |--------------------------------------------------------------------------
    */
    'lockout' => [

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

        // IPs and emails that never get recorded and are never locked out.
        // Localhost is whitelisted by default.
        'whitelist' => [
            'ips' => [
                '127.0.0.1',
                '::1',
            ],
            // Emails that can always log in, even when they would be locked out.
            'emails' => [],
        ],

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
    ],

    /*
    |--------------------------------------------------------------------------
    | Admin pages
    |--------------------------------------------------------------------------
    */
    'attempts' => [
        'page' => [
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
    ],

    // Active user sessions (requires SESSION_DRIVER=database). Lists sessions,
    // shows "last active" (Laravel updates `last_activity` on every request,
    // including Livewire clicks) and offers a one-click Revoke. Closing the
    // browser (without logout) or backgrounding the tab simply stops updating
    // `last_activity`, so the session ages out naturally and expires after
    // `session.lifetime`; sweep expired rows with the
    // `filament-loginguard:cleanup-sessions` command.
    'sessions' => [
        'table' => 'sessions',
        // A session whose last_activity is within this many seconds is "online".
        'online_threshold_seconds' => 60,
        // Eloquent model used to resolve a session's user_id. null = auth.providers.users.model.
        'user_model' => null,
        // Max concurrent sessions per user; null = unlimited. Oldest sessions are
        // evicted to make room when the limit is reached.
        'concurrent_limit' => null,
        // Sessions whose browser+platform fingerprint was first seen within this
        // window are flagged "New" on the sessions page.
        'new_device' => [
            'enabled' => true,
            'window_hours' => 24,
            'notification' => [
                // Disabled by default: the plugin cannot know who to notify.
                'enabled' => false,
                'to' => [],
                'queue' => false,
            ],
        ],
        'page' => [
            'enabled' => true,
            'slug' => 'user-sessions',
            'cluster' => null,
            'navigation_label' => null,
            'navigation_icon' => 'heroicon-o-computer-desktop',
            'navigation_group' => null,
            'navigation_sort' => null,
            // Same authorize semantics as attempts.page.authorize.
            'authorize' => null,
        ],
    ],
];
