# Changelog

All notable changes to `filament-loginguard` will be documented in this file.

## v0.6.1 - 2026-10-05

Repairs the v0.5 → v0.6 schema/lock-state upgrade path. If you upgraded straight from v0.5.0 to v0.6.0, this release is required: v0.6.0 edited already-released migrations, so upgraded databases kept the old NOT NULL history schema and never received backfilled locks.

### Fixed

- **P0:** `filament_loginguard_lockout_histories.ip/email` are now made nullable by a new alter migration. v0.6.0 edited the create migration instead of adding one, so v0.5 databases kept NOT NULL columns and the first scoped lockout insert would fail (500 on login). Released migrations are no longer modified; all paths (fresh, v0.5 → v0.6.1, v0.6.0 → v0.6.1) converge on the same schema.
- **P0:** active v0.5 locks are backfilled into `filament_loginguard_locks` (both the IP and the email scope, preserving the old `ip OR email` enforcement semantics) instead of silently disappearing after the upgrade.
- The escalation lookup is now scope-aware `MAX(lockout_count)` — IP scope reads `where('ip', $ip)`, email scope `where('email', $email)`, pair scope the exact pair. Pre-v0.6 history rows (with both columns filled) naturally count towards the IP and email ladders without synthetic backfill; escalation no longer resets after upgrading.
- Admin unblock now releases the **pair** scope as well (`releaseLocksForPair()`); previously, in per-pair tracking mode, the pair lock survived the unblock while the UI reported success. The "Locked" filter and the attempts cleanup command also account for pair locks now, and the pair scope key is built with the concat operator native to the current database (CONCAT on MySQL/MariaDB).
- `releaseLock()` accepts a reason (`self_unlock`, `admin_unblock`, `successful_login`) and records an `unlocked` security event with the scope metadata — but only when a lock row was actually deleted, so no-op releases never pollute the event log. `lockout_started` events now carry the scope too.
- The locks table's `scope_key` is widened to 320 characters (emails can exceed 191; a pair key is up to 45 + 1 + 254) and `scope_type` to 16.

### Changed

- `recordFailure()` wraps window rollover, increment, threshold check and lock application in a transaction with a `lockForUpdate()` on the attempt row, closing the rollover race for the same (ip, email) pair. Cross-row aggregate races (two different emails from one IP failing simultaneously) are narrowed but not fully eliminated.

## v0.6.0 - 2026-10-05

### Added

- Charts widget on the Login Attempts page: a daily failed-attempts trend (7/30-day filter) and Top-10 leaderboards for attacked emails and source IPs. Charts read from the new event log, so the history is accurate across window resets and cleanups; leaderboards aggregate across IPs/emails correctly.
- Append-only security event log (`filament_loginguard_events`): every failed login, successful login, lockout and unlock is recorded. This is the data source for the charts and the 24h stats widget.
- Scoped lock-state table (`filament_loginguard_locks`): IP locks and email locks are now fully independent rows, so releasing an email lock (self-unlock, admin unblock, successful login) can never clear an IP lock that shares the same attempt row.
- CSV export for the Login Attempts and User Sessions admin pages, built on Filament's export system (queued, with column mapping and a signed download link). Emails are sanitized against CSV formula injection. Only CSV is offered (`ExportFormat::Csv`).

### Fixed

- **Breaking (architecture):** lock state moved out of the attempts table. A single attempt row could previously hold both the IP lock and the email lock in one `locked_until` column — clearing the email lock also cleared the IP lock on the same row, and admin "unblock" on one row left the rest of the IP's rows locked while the UI showed them unlocked. Locks are now their own table; the `locked_until` column on attempts is legacy only.
- Self-unlock confirmation form now posts to the full signed URL (`request()->fullUrl()`), preserving the `expires`/`signature` query string. The previous form action dropped the query string, which would have caused a 403 on the real flow (tests only exercised the URL directly, not the rendered form).
- The stats widget's "successful logins (24h)" now counts real success events instead of summing lifetime `success_count` counters; "locked out now" counts the lock-state table directly (early-released locks disappear immediately) instead of a DB-specific `||` concat that does not work on MySQL.
- The charts' "24h" leaderboards now use a rolling `now()->subDay()` window instead of "since midnight" semantics.
- The attempts cleanup command no longer sweeps rows whose IP or email scope still has an active lock.

### Changed

- **Breaking:** the `pages.attempts.stats_widget` config key now controls only the numeric stats widget; the new `pages.attempts.charts` key (default `true`) controls the charts, and the new `pages.attempts.export` / `pages.sessions.export` keys (default `true`) control the CSV export actions.
- **Breaking:** lockout history rows are now scoped (`ip` or `email` set, the other null) instead of always carrying both values.

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
