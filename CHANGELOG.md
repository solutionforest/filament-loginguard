# Changelog

All notable changes to `filament-loginguard` will be documented in this file.

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
