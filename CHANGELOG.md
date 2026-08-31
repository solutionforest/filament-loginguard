# Changelog

All notable changes to `filament-loginguard` will be documented in this file.

## Unreleased

### Changed

- **Breaking:** the new-device notification (`sessions.new_device.notifications`) now emails the account owner instead of a static `mail.to` recipient list. The `sessions.new_device.notifications.mail.to` config key is removed; only `mail.queue` remains. Accounts without an email are skipped.

## v0.3.0 - 2026-08-26

### Added

- Opt-in auto-scheduling via `maintenance.cleanup_attempts` / `maintenance.cleanup_sessions`. When `enabled`, the package registers the corresponding cleanup command with Laravel's scheduler using the configured `expression` cron value (`cleanup-sessions` only when `SESSION_DRIVER=database`).

### Changed

- **Breaking:** renamed `filament-loginguard:cleanup` to `filament-loginguard:cleanup-attempts` for clarity (the command only clears attempt records). Update any scheduled tasks or scripts that reference the old name.

### Fixed

- Removed `publishMigrations()` / `askToRunMigrations()` from the install command. Migrations auto-run, so the publish workflow produced duplicate migrations (e.g. a `create_filament_loginguard_attempts_table` conflict) for apps that had already published them. Existing apps with a stale published `filament-loginguard` migration should delete it before running `migrate`.

## v0.2.0 - 2026-08-25

### Added

- User Sessions page (requires `SESSION_DRIVER=database`): lists active sessions with a human-readable "last active" state and a one-click Revoke.
- `filament-loginguard:cleanup-sessions` command to sweep expired session rows (Laravel's session GC is probabilistic and can leave stale rows behind).
- `LoginLockedOut` event, dispatched on every lockout, for custom alerting (Slack, webhooks, etc.).
- Stats overview widget on the attempts page: failed attempts (24h), currently locked out, successful logins (24h). Toggle via `pages.attempts.stats_widget`.
- Success tracking on attempt rows (`success_count`, `last_success_at`).
- New-device detection via a browser+platform fingerprint; flags sessions as "New" within a configurable window, with an optional first-sighting notification (`sessions.new_device.*`).
- Per-user concurrent session limit enforcement, evicting the oldest sessions (`sessions.concurrent_limit`).
- Package migrations now run automatically; no need to publish and run them manually.

### Changed

- **Breaking:** restructured the config file into three top-level groups — `lockout` (brute-force protection), `sessions` (session tracking behavior), `pages` (admin page wiring for both features):
  - Flat top-level keys (`enabled`, `max_attempts`, `lockout_minutes`, `ban_hours`, `attempts_window_minutes`, `tracking.*`, `whitelisted_ips`, `whitelisted_emails`, `notifications.*`) moved under `lockout.*`.
  - `lockout_minutes` → `lockout.initial_minutes`; `ban_hours` → `lockout.escalation_hours`.
  - `whitelisted_ips` / `whitelisted_emails` → `lockout.whitelist.ips` / `lockout.whitelist.emails`.
  - `admin_page.*` → `pages.attempts.*`; the new sessions page config lives at `pages.sessions.*`.
  - `sessions.new_device.notification.*` → `sessions.new_device.notifications.*`, with `to`/`queue` nested under `.mail`.
  - Republish the config file (`php artisan vendor:publish --tag="filament-loginguard-config" --force`) and update any customized values to the new key paths.
  
- "Locked until" and "Last attempt" columns now render as relative, badge-styled times (e.g. "15 minutes", "15 minutes ago") instead of absolute datetimes, with the exact datetime available on hover.
- The "online now" threshold is now `sessions.online_threshold_seconds` (default 60s), narrowed from 5 minutes, so only genuinely-active sessions show "Online now".
- Empty "Successful" and "New device" table cells render a "-" placeholder instead of a 0 badge or blank cell.

### Fixed

- `LoginLockedOut` dispatch on Laravel 11 (named arguments aren't supported there).

## v0.1.0 - 2026-08-25

### Added

- Track user agents and show a human-readable "Device" column (e.g. "Chrome on macOS") in the login attempts table.

### Changed

- Renamed the browser column to "Device".
- Hide the "Lockouts" column by default.
- Only offer "Unblock" on records that are actually locked.
- Removed the delete actions from the attempts table.

### Fixed

- A successful login no longer resets the failed-attempt counters of other accounts sharing the same IP.

## v0.0.1 - 2026-08-21

- Initial release
