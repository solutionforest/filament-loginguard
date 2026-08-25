# Changelog

All notable changes to `filament-loginguard` will be documented in this file.

## Unreleased

### Changed

- **Breaking:** restructured `config/filament-loginguard.php` for consistency:
  - `lockout.lockout_minutes` → `lockout.initial_minutes`
  - `lockout.ban_hours` → `lockout.escalation_hours`
  - `attempts.page.*` → `pages.attempts.*`
  - `sessions.page.*` → `pages.sessions.*`
  - `sessions.new_device.notification.*` → `sessions.new_device.notifications.*`, with `to`/`queue` now nested under `.mail` to match `lockout.notifications.mail.*`
  - Republish the config file (`php artisan vendor:publish --tag="filament-loginguard-config" --force`) and update any customized values to the new key paths.

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
