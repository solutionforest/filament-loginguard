# Changelog

All notable changes to `filament-loginguard` will be documented in this file.

## Unreleased

### Added

- Charts widget on the Login Attempts page: a daily failed-attempts trend (7/30-day filter) and Top-10 leaderboards for attacked emails and source IPs, all based on the windowed attempt counts. Toggled with the existing `pages.attempts.stats_widget` option.

## v0.5.0 - 2026-09-28

### Added

- IP address normalization: IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) are reduced to their plain IPv4 form, and IPv6 addresses are canonicalized, so the same client always maps to the same lockout key regardless of protocol or textual representation.
- Trusted proxy support via `lockout.trusted_proxies` (IPs or CIDR ranges): when the immediate request IP matches a trusted proxy, the real client IP is read from the `X-Forwarded-For` header (walking right-to-left past trusted proxies, so clients cannot spoof it).
- Composite indexes on `filament_loginguard_attempts` (`ip, last_attempt_at` and `email, last_attempt_at`) so the per-IP / per-email aggregate SUM queries stay fast as the table grows.
- Self-service unlock (anti-DoS): when `lockout.notifications.self_unlock.enabled`, the lockout email sent to the blocked address carries a signed, single-use "unlock now" link that clears the email lock immediately. Attempt counters are kept (repeat lockouts still escalate) and IP locks are never lifted through the link. Off by default.
- Append-only lockout history table (`filament_loginguard_lockout_histories`): every applied lockout is recorded there, so the attempts cleanup command can delete stale rows without ever resetting the escalation ladder.
- Windowed attempt counting via `window_started_at`: the attempt counter is now a true fixed window — a slow drip with gaps shorter than `attempts_window_minutes` no longer accumulates forever; each window only counts failures that actually happened inside it.

### Changed

- **Breaking:** the minimum supported Filament version is now 5.7.6 (earlier 5.x releases have known security advisories).
- Clarified the README install instructions: `filament-loginguard:install` publishes the config file only; migrations run automatically and `php artisan migrate` applies them.
- **Breaking:** the self-unlock email is now sent to the blocked address itself, independent of `lockout.notifications.mail.to` — admins no longer receive (and can no longer act on) the victim's unlock link, and self-unlock works even with no admin recipients configured.
- **Breaking:** the self-unlock link now shows a confirmation page (GET) and performs the unlock on POST; the URL carries an opaque random token instead of the email address, so the address never appears in proxy logs, browser history or mail-scanner trails.
- **Breaking:** session security features (new-device detection, new-device notifications, concurrent-session limit) are now gated by the new `sessions.enabled` config key instead of `pages.sessions.enabled` — hiding the admin page no longer silently disables the security behavior.
- **Breaking:** the stats widget now counts failures inside active windows only, actual successful logins (not rows), and distinct locked (IP, email) pairs from the history table — matching real-world semantics.
- Failed-attempt counters are incremented atomically in SQL, so concurrent login failures can no longer lose updates under high load.
- The bulk revoke action on the sessions page no longer deletes the current session, and the split `authorize_view` / `authorize_unblock` / `authorize_revoke` page abilities let admins grant read-only or action-specific access.

## v0.4.0 - 2026-08-31

### Added

- Livewire test helpers `assertLoginGuardAttempts`, `assertLoginGuardLocked`, and `assertLoginGuardNotLocked`, mixed into `Livewire\Features\SupportTesting\Testable` for asserting login-guard state in application tests.

### Changed

- **Breaking:** the new-device notification (`sessions.new_device.notifications`) now emails the account owner instead of a static `mail.to` recipient list. The `sessions.new_device.notifications.mail.to` config key is removed; only `mail.queue` remains. Accounts without an email are skipped.

### Removed

- **Breaking:** removed the unused `FilamentLoginGuard` class and the `FilamentLoginGuard` facade alias (skeleton stubs that exposed no API). Use the `LoginGuardService` (resolvable via the container) instead.
