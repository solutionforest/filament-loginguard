# Filament LoginGuard

[![Latest Version on Packagist](https://img.shields.io/packagist/v/solution-forest/filament-loginguard.svg?style=flat-square)](https://packagist.org/packages/solution-forest/filament-loginguard)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/solutionforest/filament-loginguard/tests.yml?branch=5.x&label=tests&style=flat-square)](https://github.com/solutionforest/filament-loginguard/actions?query=workflow%3Atests+branch%3A5.x)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/solutionforest/filament-loginguard/fix-code-style.yml?branch=5.x&label=code%20style&style=flat-square)](https://github.com/solutionforest/filament-loginguard/actions?query=workflow%3A"fix-code-style"+branch%3A5.x)
[![Total Downloads](https://img.shields.io/packagist/dt/solution-forest/filament-loginguard.svg?style=flat-square)](https://packagist.org/packages/solution-forest/filament-loginguard)

Brute force login protection for Filament panels and Laravel apps. Failed login attempts are recorded per IP/email pair in a database table; once a threshold is reached the IP and/or email is locked out for a configurable, escalating duration. Whitelists bypass protection entirely, admins are notified by email on lockouts, and a panel page lets you inspect, unblock and delete recorded attempts.

> [!NOTE]
> Filament already throttles its login page at 5 attempts per minute per IP. This package adds the missing **lockout layer** on top of that: persistent tracking, escalating bans, per-email protection and an admin UI.

## Requirements

- PHP 8.3+
- Laravel 11, 12 or 13
- Filament v5 (≥ 5.6.5 — earlier 5.x releases have known security advisories; Livewire 4)

## Installation

You can install the package via composer:

```bash
composer require solution-forest/filament-loginguard
```

Publish and run the migrations, and publish the config file:

```bash
php artisan vendor:publish --tag="filament-loginguard-migrations"
php artisan vendor:publish --tag="filament-loginguard-config"
php artisan migrate
```

Or run the interactive install command, which does all of the above:

```bash
php artisan filament-loginguard:install
```

Optionally, you can publish the views and translations using:

```bash
php artisan vendor:publish --tag="filament-loginguard-views"
php artisan vendor:publish --tag="filament-loginguard-translations"
```

To enable the **admin page** (view / unblock / delete recorded attempts), register the plugin in your panel provider, e.g. `app/Providers/Filament/AdminPanelProvider.php`:

```php
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;

public function panel(Panel $panel): Panel
{
    return $panel
        // ...
        ->plugin(FilamentLoginGuardPlugin::make());
}
```

The core protection works **without** registering the plugin — only the admin page needs it.

## How it works

The package listens to three Laravel auth events, so it protects **every** login flow in your app (Filament panels, Fortify, custom controllers):

| Event | Action |
| --- | --- |
| `Illuminate\Auth\Events\Attempting` | If the IP or email is currently locked out, a `ValidationException` with the lockout message is thrown before any credential work happens. |
| `Illuminate\Auth\Events\Failed` | The failure is recorded for the (IP, email) pair. When the threshold is reached, the IP and/or email is locked out and admins are notified by email. |
| `Illuminate\Auth\Events\Login` | A successful login clears all counters and locks for that IP and email. |

Lockout semantics:

- Rows are stored per **(IP, email) pair** in the `filament_loginguard_attempts` table.
- With `tracking.per_ip` enabled, the **sum** of attempts across all emails from one IP triggers a lockout of that IP — rotating emails doesn't help attackers. `tracking.per_email` does the same across IPs for one email.
- Lock durations **escalate**: the first lockout lasts `lockout_minutes`; the 2nd, 3rd and subsequent lockouts use `ban_hours` (e.g. `[24, 72, 168]` = 1 day, 3 days, 7 days+). The last value repeats for every further lockout.
- Attempts **decay**: failures older than `attempts_window_minutes` no longer count, and the counter restarts.
- A lock is **never extended** by further attempts while it is active; a successful login resets everything (forgiving legitimate owners).
- The lockout message is rendered in the Filament login form (`data.email` error key) and as a standard `email` validation error in non-Filament forms (redirect back for web requests, 422 for JSON).
- Localhost (`127.0.0.1`, `::1`) is whitelisted by default.

## Configuration

This is the contents of the published config file (`config/filament-loginguard.php`):

```php
return [
    'enabled' => true,               // master switch
    'max_attempts' => 10,            // failures allowed inside the window before a lockout
    'lockout_minutes' => 15,         // duration of the first lockout
    'ban_hours' => [24, 72, 168],    // 2nd, 3rd, 4th+ lockout durations; last value repeats
    'attempts_window_minutes' => 30, // decay + aggregate counting window

    'tracking' => [
        'per_ip' => true,            // aggregate attempts across emails per IP
        'per_email' => true,         // aggregate attempts across IPs per email
        'guards' => [],              // restrict to specific guards, e.g. ['web']; empty = all
    ],

    'whitelisted_ips' => ['127.0.0.1', '::1'],
    'whitelisted_emails' => [],

    'notifications' => [
        'enabled' => true,
        'mail' => [
            'to' => [],              // admin addresses; empty = no notifications
            'cooldown_minutes' => 60, // at most one notification per IP per window
            'queue' => false,        // false = sync; queue name string = queued
        ],
    ],

    'admin_page' => [
        'enabled' => true,
        'slug' => 'login-guard',
        'cluster' => null,           // optional Filament Cluster class-string to nest the page under
        'navigation_label' => null,  // null falls back to translations
        'navigation_icon' => 'heroicon-o-shield-exclamation',
        'navigation_group' => null,
        'navigation_sort' => null,
        'authorize' => null,         // ability name checked via $user->can(); null = any authenticated panel user
    ],
];
```

> [!WARNING]
> The admin page is visible to **any authenticated panel user** by default. Restrict it with the `authorize` option and a Gate, e.g.:
>
> ```php
> // config/filament-loginguard.php
> 'admin_page' => ['authorize' => 'view-filament-loginguard', /* ... */],
>
> // app/Providers/AppServiceProvider.php
> Gate::define('view-filament-loginguard', fn (User $user) => $user->can('access-admin-settings'));
> ```

## Maintenance

Delete stale, expired records (attempts outside the decay window with no active lock):

```bash
php artisan filament-loginguard:cleanup
php artisan filament-loginguard:cleanup --all   # delete every record
```

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](.github/CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](.github/SECURITY.md) on how to report security vulnerabilities.

## Credits

- [Solution Forest](https://github.com/solutionforest)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
