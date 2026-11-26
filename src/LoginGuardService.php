<?php

namespace SolutionForest\FilamentLoginGuard;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Support\Arr;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Str;
use SolutionForest\FilamentLoginGuard\Models\KnownDevice;
use SolutionForest\FilamentLoginGuard\Models\LockoutHistory;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Models\LoginGuardLock;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;
use SolutionForest\FilamentLoginGuard\Models\UserSession;
use SolutionForest\FilamentLoginGuard\Notifications\AccountLockedNotification;
use SolutionForest\FilamentLoginGuard\Notifications\NewDeviceLoginNotification;
use SolutionForest\FilamentLoginGuard\Support\IpAddress;
use SolutionForest\FilamentLoginGuard\Support\ParsesUserAgent;

final class LoginGuardService
{
    public function isEnabled(): bool
    {
        return (bool) config('filament-loginguard.lockout.enabled', true);
    }

    /**
     * Whitelisted IPs and emails bypass recording AND lockout checks entirely.
     */
    public function isWhitelisted(string $ip, ?string $email): bool
    {
        $ip = IpAddress::normalize($ip);

        $whitelistedIps = array_map(
            static fn (mixed $entry): string => IpAddress::normalize(is_string($entry) ? $entry : ''),
            (array) config('filament-loginguard.lockout.whitelist.ips', []),
        );

        if (in_array($ip, $whitelistedIps, true)) {
            return true;
        }

        if ($email === null) {
            return false;
        }

        $whitelistedEmails = array_map(
            static fn (mixed $entry): string => strtolower(is_string($entry) ? $entry : ''),
            (array) config('filament-loginguard.lockout.whitelist.emails', []),
        );

        return in_array($email, $whitelistedEmails, true);
    }

    public function isLocked(string $ip, ?string $email): bool
    {
        if (! $this->isEnabled()) {
            return false;
        }

        return $this->activeLocksQuery($ip, $email)->exists();
    }

    public function remainingLockSeconds(string $ip, ?string $email): int
    {
        /** @var string|null $lockedUntil */
        $lockedUntil = $this->activeLocksQuery($ip, $email)->max('locked_until');

        return $lockedUntil !== null ? (int) now()->diffInSeconds($lockedUntil) : 0;
    }

    /**
     * The furthest-out active lock applying to this (ip, email), or null.
     * Pass null for the IP to check only the email scope.
     */
    public function lockFor(?string $ip, ?string $email): ?Carbon
    {
        /** @var string|null $lockedUntil */
        $lockedUntil = $this->activeLocksQuery($ip, $email)->max('locked_until');

        return $lockedUntil !== null ? Carbon::parse($lockedUntil) : null;
    }

    /**
     * SQL expression that builds the pair scope key from two columns, using the
     * concat operator native to the current database connection (`||` is not
     * string concatenation on MySQL/MariaDB, so CONCAT() is used there).
     */
    public function pairScopeExpression(string $ipColumn, string $emailColumn): string
    {
        return $this->concatenate([$ipColumn, "'|'", $emailColumn]);
    }

    /** @param list<string> $expressions */
    private function concatenate(array $expressions): string
    {
        return in_array(DB::connection()->getDriverName(), ['mysql', 'mariadb', 'sqlsrv'], true)
            ? 'CONCAT(' . implode(', ', $expressions) . ')'
            : '(' . implode(' || ', $expressions) . ')';
    }

    /** Correlated lock lookup shared by the attempts table filter and retention cleanup. */
    public function activeLocksForAttempt(): QueryBuilder
    {
        $ip = 'filament_loginguard_attempts.ip';
        $email = 'filament_loginguard_attempts.email';
        $mapped = $this->concatenate(["'::ffff:'", $ip]);
        $unmapped = DB::connection()->getDriverName() === 'sqlsrv' ? "SUBSTRING({$ip}, 8, 45)" : "SUBSTR({$ip}, 8)";
        $alternate = "CASE WHEN {$ip} LIKE '::ffff:%.%.%.%' THEN {$unmapped}"
            . " WHEN {$ip} LIKE '%.%.%.%' AND {$ip} NOT LIKE '%:%' THEN {$mapped} ELSE {$ip} END";
        $pair = $this->pairScopeExpression($ip, $email);
        $alternatePair = $this->pairScopeExpression($alternate, $email);

        return DB::table('filament_loginguard_locks')
            ->selectRaw('1')
            ->where('locked_until', '>', now())
            ->where(function (QueryBuilder $scopes) use ($ip, $alternate, $email, $pair, $alternatePair): void {
                $scopes->where(fn (QueryBuilder $q) => $q->where('scope_type', LoginGuardLock::SCOPE_IP)->whereIn('scope_key', [DB::raw($ip), DB::raw($alternate)]))
                    ->orWhere(fn (QueryBuilder $q) => $q->where('scope_type', LoginGuardLock::SCOPE_EMAIL)->whereColumn('scope_key', $email))
                    ->orWhere(fn (QueryBuilder $q) => $q->where('scope_type', LoginGuardLock::SCOPE_PAIR)->whereIn('scope_key', [DB::raw($pair), DB::raw($alternatePair)]));
            });
    }

    /**
     * Active locks that apply to the given request: the IP's lock and/or the
     * email's lock (and/or the exact pair's lock when per-pair tracking is
     * used), each a fully independent row in the locks table.
     *
     * @return Builder<LoginGuardLock>
     */
    private function activeLocksQuery(?string $ip, ?string $email): Builder
    {
        $ips = $ip === null ? [] : IpAddress::storedKeys($ip);

        return LoginGuardLock::activeQuery()
            ->where(function (Builder $query) use ($ips, $email): void {
                $query->where(function (Builder $q) use ($ips): void {
                    $q->where('scope_type', LoginGuardLock::SCOPE_IP)
                        ->whereIn('scope_key', $ips);
                });

                if (filled($email)) {
                    $query->orWhere(function (Builder $q) use ($email): void {
                        $q->where('scope_type', LoginGuardLock::SCOPE_EMAIL)
                            ->where('scope_key', $email);
                    });

                    if ($ips !== []) {
                        $query->orWhere(function (Builder $q) use ($ips, $email): void {
                            $q->where('scope_type', LoginGuardLock::SCOPE_PAIR)
                                ->whereIn('scope_key', array_map(fn (string $ip): string => $ip . '|' . $email, $ips));
                        });
                    }
                }
            });
    }

    /**
     * Record one failed attempt. Returns a LockoutResult describing whether THIS attempt
     * triggered a lockout (so the listener can throw + notify).
     *
     * The counter is a fixed window: all attempts with `window_started_at` inside
     * `attempts_window_minutes` accumulate; the first failure after the window
     * expired resets the counter and starts a new window. This matches the README
     * semantics — a slow drip with gaps shorter than the window cannot accumulate
     * forever, because each window only counts failures that actually happened
     * inside it.
     *
     * The pair's row is locked for rollover and increment. On MySQL and MariaDB,
     * current reads also cover scope totals so an earlier snapshot cannot miss
     * attempts committed by concurrent transactions.
     */
    public function recordFailure(string $ip, string $email, ?string $userAgent = null): LockoutResult
    {
        if ($userAgent !== null && Str::length($userAgent) > 255) {
            $userAgent = Str::substr($userAgent, 0, 252) . '...';
        }

        $ips = IpAddress::storedKeys($ip);
        $ip = $ips[0];

        $driver = DB::connection()->getDriverName();
        $useCurrentScopeReads = in_array($driver, ['mysql', 'mariadb'], true);

        /** @var LockoutResult $result */
        $result = DB::transaction(function () use ($ip, $ips, $email, $userAgent, $driver, $useCurrentScopeReads): LockoutResult {
            $now = Carbon::now();
            $maxAttempts = filament_loginguard_config_int('filament-loginguard.lockout.max_attempts', 10);
            $windowMinutes = filament_loginguard_config_int('filament-loginguard.lockout.attempts_window_minutes', 30);
            $cutoff = $now->copy()->subMinutes(max(1, $windowMinutes));
            $trackIp = (bool) config('filament-loginguard.lockout.tracking.per_ip', true);
            $trackEmail = (bool) config('filament-loginguard.lockout.tracking.per_email', true);

            if ($driver === 'sqlite') {
                // SQLite cannot always promote a read transaction to a writer.
                // Start with a conditional rollover so writers wait before taking a snapshot.
                LoginAttempt::query()
                    ->where('ip', $ip)
                    ->where('email', $email)
                    ->where('window_started_at', '<=', $cutoff)
                    ->update(['attempts' => 0, 'window_started_at' => $now]);
            }

            $identity = ['ip' => $ip, 'email' => $email];

            $pair = LoginAttempt::query();
            $pair->where($identity);

            // Locking a missing MySQL row takes gap locks that can conflict
            // with concurrent first inserts, even for different pairs.
            $mayExist = ! $useCurrentScopeReads || (clone $pair)->exists();
            $pair->lockForUpdate();

            // The fallback inside createOrFirst must read under the same lock
            // if another request created this pair after the existence check.
            $row = ($mayExist ? (clone $pair)->first() : null) ?? $pair->createOrFirst($identity);
            $key = $row->id;

            // Fixed window: if the current window expired, restart it from zero. The
            // atomic UPDATE below then bumps the (possibly reset) counter by one.
            $windowExpired = $row->window_started_at === null
                || $row->window_started_at->lte($cutoff);

            if ($windowExpired) {
                LoginAttempt::query()
                    ->whereKey($key)
                    ->update(['attempts' => 0, 'window_started_at' => $now]);
            }

            LoginAttempt::query()
                ->whereKey($key)
                ->update([
                    'attempts' => DB::raw('attempts + 1'),
                    'last_attempt_at' => $now,
                    'user_agent' => $userAgent,
                ]);

            // Aggregate sums count attempts of all rows of the same IP (or same email)
            // whose window is still active. A threshold breach locks the *scope*
            // (the IP itself, or the email itself) — never individual attempt rows.
            $lockScopes = [];

            if ($trackIp) {
                $ipAttempts = $this->attemptsInWindow(
                    LoginAttempt::query()->toBase()->whereIn('ip', $ips),
                    $cutoff,
                    $useCurrentScopeReads,
                );

                if ($ipAttempts >= $maxAttempts) {
                    $lockScopes[] = [LoginGuardLock::SCOPE_IP, $ip];
                }
            }

            if ($trackEmail) {
                $emailAttempts = $this->attemptsInWindow(
                    LoginAttempt::query()->toBase()->where('email', $email),
                    $cutoff,
                    $useCurrentScopeReads,
                );

                if ($emailAttempts >= $maxAttempts) {
                    $lockScopes[] = [LoginGuardLock::SCOPE_EMAIL, $email];
                }
            }

            if (! $trackIp && ! $trackEmail) {
                $attempts = $this->attemptsInWindow(
                    LoginAttempt::query()->toBase()->whereIn('ip', $ips)->where('email', $email),
                    $cutoff,
                    $useCurrentScopeReads,
                );

                if ($attempts >= $maxAttempts) {
                    $lockScopes[] = [LoginGuardLock::SCOPE_PAIR, $ip . '|' . $email];
                }
            }

            if ($lockScopes === []) {
                return new LockoutResult(locked: false);
            }

            // An already-active lock belongs to an earlier attempt. Concurrent
            // failures that passed the listener's pre-check cannot extend it.
            $locked = false;
            $lockoutRecords = [];
            $maxLockedUntil = null;

            foreach ($lockScopes as [$scopeType, $scopeKey]) {
                $scopeLocks = LoginGuardLock::query();
                $scopeLocks->where('scope_type', $scopeType)
                    ->whereIn('scope_key', $this->storedScopeKeys($scopeType, $scopeKey))
                    ->orderByDesc('locked_until')
                    ->lockForUpdate();
                $lock = $scopeLocks->first();

                if ($lock !== null && $lock->locked_until->gt($now)) {
                    continue;
                }

                // The escalation position is derived from the append-only history
                // table, not from a deletable counter — the cleanup command must
                // never be able to reset the ladder. The lookup is scope-aware:
                //   IP scope   → rows whose ip matches (v0.5 legacy rows with
                //                both ip+email filled are naturally included)
                //   EMAIL scope → rows whose email matches
                //   PAIR scope → the exact (ip, email) pair only
                // so pre-v0.6 history keeps counting towards the escalation
                // ladder without any backfill or synthetic rows.
                $history = match ($scopeType) {
                    LoginGuardLock::SCOPE_IP => LockoutHistory::query()->whereIn('ip', $ips),
                    LoginGuardLock::SCOPE_EMAIL => LockoutHistory::query()->where('email', $scopeKey),
                    default => LockoutHistory::query()->whereIn('ip', $ips)->where('email', $email),
                };
                $newCount = filament_loginguard_intval($history
                    ->orderByDesc('lockout_count')
                    ->lockForUpdate()
                    ->value('lockout_count')) + 1;

                $durationMinutes = $this->durationForLockoutCount($newCount);
                $lockedUntil = $now->copy()->addMinutes($durationMinutes);

                if ($lock !== null && $lock->locked_until->gte($lockedUntil)) {
                    continue;
                }

                $values = ['locked_until' => $lockedUntil, 'escalation_count' => $newCount];
                $canonicalScope = LoginGuardLock::query();
                $canonicalScope->lockForUpdate();
                $canonicalLock = $canonicalScope->firstOrCreate(
                    ['scope_type' => $scopeType, 'scope_key' => $scopeKey],
                    $values,
                );

                if (! $canonicalLock->wasRecentlyCreated) {
                    if ($canonicalLock->locked_until->gt($now) || $canonicalLock->locked_until->gte($lockedUntil)) {
                        continue;
                    }

                    $canonicalLock->update($values);
                }

                $lockoutRecords[] = [
                    'scope_type' => $scopeType,
                    'scope_key' => $scopeKey,
                    'ip' => $scopeType === LoginGuardLock::SCOPE_EMAIL ? null : ($scopeType === LoginGuardLock::SCOPE_PAIR ? explode('|', $scopeKey, 2)[0] : $scopeKey),
                    'email' => $scopeType === LoginGuardLock::SCOPE_IP ? null : ($scopeType === LoginGuardLock::SCOPE_PAIR ? explode('|', $scopeKey, 2)[1] : $scopeKey),
                    'locked_at' => $now,
                    'locked_until' => $lockedUntil,
                    'lockout_count' => $newCount,
                    'duration_minutes' => $durationMinutes,
                    'triggered_by_ip' => $ip,
                    'triggered_by_email' => $email,
                    'created_at' => $now,
                    'updated_at' => $now,
                ];

                $locked = true;

                if ($maxLockedUntil === null || $lockedUntil->gt($maxLockedUntil)) {
                    $maxLockedUntil = $lockedUntil;
                }
            }

            if ($lockoutRecords !== []) {
                // Escalation history lives in its own append-only table so the
                // attempts cleanup command can delete stale rows without ever
                // resetting the escalation ladder.
                foreach ($lockoutRecords as $record) {
                    SecurityEvent::record(
                        SecurityEvent::TYPE_LOCKOUT_STARTED,
                        $record['triggered_by_ip'],
                        $record['triggered_by_email'],
                        null,
                        null,
                        null,
                        [
                            'scope_type' => $record['scope_type'],
                            'scope_key' => $record['scope_key'],
                            'locked_until' => $record['locked_until']->toDateTimeString(),
                            'duration_minutes' => $record['duration_minutes'],
                        ],
                    );
                }

                // History rows only persist their own columns.
                LockoutHistory::query()->insert(array_map(
                    fn (array $record): array => Arr::except($record, ['scope_type', 'scope_key']),
                    $lockoutRecords,
                ));
            }

            if (! $locked) {
                return new LockoutResult(locked: false);
            }

            $seconds = $maxLockedUntil !== null
                ? (int) $now->diffInSeconds($maxLockedUntil)
                : 0;
            $seconds = max(0, $seconds);

            return new LockoutResult(
                locked: true,
                secondsRemaining: $seconds,
                minutes: (int) ceil($seconds / 60),
            );
        }, attempts: $useCurrentScopeReads ? 8 : 1);

        return $result;
    }

    private function attemptsInWindow(QueryBuilder $scope, Carbon $cutoff, bool $useCurrentRead): int
    {
        $scope->where('window_started_at', '>', $cutoff);

        if ($useCurrentRead) {
            // MySQL's ordinary reads can keep a snapshot from before another
            // pair's update. The locking read uses the latest committed rows.
            $scope->lockForUpdate();
        }

        return filament_loginguard_intval($scope->sum('attempts'));
    }

    /**
     * First lockout = initial_minutes; 2nd = escalation_hours[0]; 3rd = escalation_hours[1]; ... last entry repeats.
     */
    public function durationForLockoutCount(int $lockoutCount): int
    {
        $baseMinutes = filament_loginguard_config_int('filament-loginguard.lockout.initial_minutes', 15);

        if ($lockoutCount <= 1) {
            return $baseMinutes;
        }

        /** @var array<int, int> $escalationHours */
        $escalationHours = (array) config('filament-loginguard.lockout.escalation_hours', []);

        if ($escalationHours === []) {
            return $baseMinutes;
        }

        $index = min($lockoutCount - 2, count($escalationHours) - 1);

        return (int) $escalationHours[$index] * 60;
    }

    /**
     * Successful login: clear the failed-attempt counters of this (ip, email) pair
     * and lift the EMAIL lock for that address only.
     *
     * A successful login proves the credentials are valid, so the email scope's
     * lock is lifted (forgiving the legitimate owner). The IP scope is left
     * alone: one valid login from a shared IP must not unlock the whole IP,
     * which would let attackers behind the same NAT keep brute-forcing.
     */
    public function resetForSuccess(string $ip, ?string $email): void
    {
        if (! $this->isEnabled()) {
            return;
        }

        $query = LoginAttempt::query()->whereIn('ip', IpAddress::storedKeys($ip));

        if (filled($email)) {
            $query->where('email', $email);
        }

        $query->update([
            'attempts' => 0,
            'lockout_count' => 0,
            'last_attempt_at' => null,
            'window_started_at' => null,
        ]);

        if (filled($email)) {
            $this->releaseLock(LoginGuardLock::SCOPE_EMAIL, $email, reason: 'successful_login');
        }
    }

    /**
     * Record a successful login: stamp the success counter, clear the failed
     * attempts for this (ip, email) row and lift the EMAIL lock.
     */
    public function recordSuccess(string $ip, string $email): void
    {
        if (! $this->isEnabled()) {
            return;
        }

        $identity = ['ip' => IpAddress::storedKeys($ip)[0], 'email' => $email];
        $usesMysql = in_array(DB::connection()->getDriverName(), ['mysql', 'mariadb'], true);

        DB::transaction(function () use ($ip, $email, $identity, $usesMysql): void {
            $attempts = LoginAttempt::query();

            if ($usesMysql) {
                // Create an absent pair before the reset can take a gap lock
                // on its location. Keep duplicate-key recovery on a current read.
                $exists = (clone $attempts)->where($identity)->exists();
                $attempts->lockForUpdate();

                if (! $exists) {
                    $attempts->createOrFirst($identity);
                }
            }

            $this->resetForSuccess($ip, $email);

            $row = $attempts->firstOrCreate($identity);
            $row->forceFill([
                'success_count' => (int) $row->success_count + 1,
                'last_success_at' => Carbon::now(),
            ])->save();
        }, attempts: $usesMysql ? 8 : 1);
    }

    /**
     * Record the browser+platform fingerprint for a user on login. When the device
     * is seen for the first time, notify the account owner (if it has an email).
     */
    public function recordDevice(int $userId, ?string $userAgent, ?string $email): void
    {
        if (! (bool) config('filament-loginguard.sessions.new_device.enabled', true)) {
            return;
        }

        $fingerprint = ParsesUserAgent::parseDeviceName($userAgent);

        if ($fingerprint === null) {
            return;
        }

        /** @var KnownDevice $device */
        $device = KnownDevice::query()->firstOrCreate(
            ['user_id' => $userId, 'fingerprint' => $fingerprint],
            ['first_seen_at' => Carbon::now()],
        );

        if ($device->wasRecentlyCreated && filled($email)) {
            $this->notifyNewDevice($fingerprint, $email);
        }
    }

    /**
     * Evict the oldest sessions beyond the per-user concurrent limit, making room
     * for the session that is being created right now.
     */
    public function enforceConcurrentLimit(int $userId): void
    {
        $limit = filament_loginguard_config_int('filament-loginguard.sessions.concurrent_limit', 0);

        if ($limit <= 0) {
            return;
        }

        /** @var Collection<int, UserSession> $sessions */
        $sessions = UserSession::query()
            ->where('user_id', $userId)
            ->orderByDesc('last_activity')
            ->get();

        if ($sessions->count() < $limit) {
            return;
        }

        $sessions->slice($limit - 1)->each->delete();
    }

    /**
     * Send the new-device notification to the account owner.
     */
    private function notifyNewDevice(string $fingerprint, string $email): void
    {
        if (! (bool) config('filament-loginguard.sessions.new_device.notifications.enabled', false)) {
            return;
        }

        $notification = new NewDeviceLoginNotification(
            email: $email,
            device: $fingerprint,
            ip: IpAddress::fromRequest(),
        );

        $queue = config('filament-loginguard.sessions.new_device.notifications.mail.queue', false);

        $notifiable = Notification::route('mail', $email);

        if (is_string($queue) && $queue !== '') {
            $notifiable->notify($notification->onQueue($queue));
        } else {
            $notifiable->notifyNow($notification);
        }
    }

    /**
     * Send the admin notification, throttled per-IP via the cache. Returns whether it was sent.
     *
     * Independent of the admin mail, a self-service unlock email is delivered to
     * the blocked address itself when `self_unlock.enabled` — so mailbox owners
     * can recover from a lockout even when no admin recipients are configured.
     */
    public function notifyLockout(string $ip, string $email, int $minutes): bool
    {
        if (! (bool) config('filament-loginguard.lockout.notifications.enabled', true)) {
            return false;
        }

        $sent = $this->notifyAdmins($ip, $email, $minutes);

        $this->sendSelfUnlockEmail($ip, $email, $minutes);

        return $sent;
    }

    /**
     * Email the admins listed in `notifications.mail.to`, throttled per IP.
     */
    private function notifyAdmins(string $ip, string $email, int $minutes): bool
    {
        $recipients = (array) config('filament-loginguard.lockout.notifications.mail.to', []);

        if ($recipients === []) {
            return false;
        }

        $cooldownMinutes = filament_loginguard_config_int('filament-loginguard.lockout.notifications.mail.cooldown_minutes', 60);
        $cacheKey = 'filament-loginguard:notified:' . $ip;

        if ($cooldownMinutes > 0 && cache()->has($cacheKey)) {
            return false;
        }

        cache()->put($cacheKey, true, $cooldownMinutes * 60);

        $notification = new AccountLockedNotification(ip: $ip, email: $email, minutes: $minutes);

        $queue = config('filament-loginguard.lockout.notifications.mail.queue', false);

        foreach ($recipients as $recipient) {
            $notifiable = Notification::route('mail', $recipient);

            if (is_string($queue) && $queue !== '') {
                $notifiable->notify($notification->onQueue($queue));
            } else {
                $notifiable->notifyNow($notification);
            }
        }

        return true;
    }

    /**
     * Email the self-service unlock link to the blocked address itself.
     * Never throttled and independent of the admin recipients: this is the
     * lockout victim's recovery path.
     */
    private function sendSelfUnlockEmail(string $ip, string $email, int $minutes): void
    {
        $url = $this->selfUnlockUrl($email);

        if ($url === null) {
            return;
        }

        $notification = new AccountLockedNotification(
            ip: $ip,
            email: $email,
            minutes: $minutes,
            unlockUrl: $url,
        );

        $queue = config('filament-loginguard.lockout.notifications.self_unlock.queue', false);

        $notifiable = Notification::route('mail', $email);

        if (is_string($queue) && $queue !== '') {
            $notifiable->notify($notification->onQueue($queue));
        } else {
            $notifiable->notifyNow($notification);
        }
    }

    /**
     * Signed, single-use URL that clears the email lock, or null when self-unlock
     * is disabled. The URL carries an opaque random token — the blocked address
     * is never exposed in the path or query string (it stays out of proxy logs,
     * browser history and mail-scanner trails). The email itself is emailed to
     * the blocked address, so only the mailbox owner can act on the link.
     */
    public function selfUnlockUrl(string $email): ?string
    {
        if (! (bool) config('filament-loginguard.lockout.notifications.self_unlock.enabled', false)) {
            return null;
        }

        $ttlMinutes = max(1, filament_loginguard_config_int('filament-loginguard.lockout.notifications.self_unlock.link_ttl_minutes', 60));
        $token = Str::random(40);

        // The opaque token maps back to the locked email inside the TTL window.
        cache()->put($this->unlockTokenKey($token), $email, $ttlMinutes * 60);

        try {
            return URL::temporarySignedRoute(
                'filament-loginguard.unlock.show',
                now()->addMinutes($ttlMinutes),
                ['token' => $token],
            );
        } catch (\Throwable) {
            // Route not registered (e.g. tests without the package routes).
            cache()->forget($this->unlockTokenKey($token));

            return null;
        }
    }

    /**
     * Resolve an opaque unlock token back to its email, or null when the token
     * is unknown/expired.
     */
    public function emailForUnlockToken(string $token): ?string
    {
        $email = cache()->get($this->unlockTokenKey($token));

        return is_string($email) && filled($email) ? $email : null;
    }

    public function forgetUnlockToken(string $token): void
    {
        cache()->forget($this->unlockTokenKey($token));
    }

    public function selfUnlockTtlSeconds(): int
    {
        return max(1, filament_loginguard_config_int('filament-loginguard.lockout.notifications.self_unlock.link_ttl_minutes', 60)) * 60;
    }

    /**
     * Self-service unlock: lift the EMAIL lock of the given address.
     *
     * Only the email scope is released; the IP scope is deliberately not touched —
     * otherwise an attacker could unlock their own IP by triggering a lock on an
     * email they control and clicking the link. Counters and escalation history
     * are kept so a repeat offender still escalates.
     */
    public function unlockEmail(string $email): int
    {
        $email = Str::lower(trim($email));

        if ($email === '') {
            return 0;
        }

        return $this->releaseLock(LoginGuardLock::SCOPE_EMAIL, $email, reason: 'self_unlock');
    }

    /**
     * Lift a single lock scope. Returns 1 when a lock was released, 0 when there
     * was no lock for the scope. A released lock is recorded as an `unlocked`
     * security event (with the release reason) — but only when a lock row was
     * actually deleted, so no-op releases never pollute the event log.
     */
    public function releaseLock(string $scopeType, string $scopeKey, string $reason = 'admin_unblock'): int
    {
        $released = filament_loginguard_intval(LoginGuardLock::query()
            ->where('scope_type', $scopeType)
            ->whereIn('scope_key', $this->storedScopeKeys($scopeType, $scopeKey))
            ->delete());

        if ($released > 0) {
            SecurityEvent::record(SecurityEvent::TYPE_UNLOCKED, null, null, null, null, null, [
                'scope_type' => $scopeType,
                'scope_key' => $scopeKey,
                'reason' => $reason,
            ]);
        }

        return $released > 0 ? 1 : 0;
    }

    /** @return non-empty-list<string> */
    private function storedScopeKeys(string $scopeType, string $scopeKey): array
    {
        if ($scopeType === LoginGuardLock::SCOPE_IP) {
            return IpAddress::storedKeys($scopeKey);
        }

        if ($scopeType === LoginGuardLock::SCOPE_PAIR && str_contains($scopeKey, '|')) {
            [$ip, $email] = explode('|', $scopeKey, 2);

            return array_map(fn (string $key): string => $key . '|' . $email, IpAddress::storedKeys($ip));
        }

        return [$scopeKey];
    }

    /**
     * Release every lock scope that applies to an (ip, email) pair: the IP
     * lock, the email lock and the exact-pair lock (used when both aggregate
     * toggles are off). Admin unblock treats the pair as one unit.
     */
    public function releaseLocksForPair(string $ip, ?string $email, string $reason = 'admin_unblock'): void
    {
        $this->releaseLock(LoginGuardLock::SCOPE_IP, $ip, $reason);

        if (filled($email)) {
            $this->releaseLock(LoginGuardLock::SCOPE_EMAIL, $email, $reason);
            $this->releaseLock(LoginGuardLock::SCOPE_PAIR, $ip . '|' . $email, $reason);
        }
    }

    /**
     * Mark a self-unlock signature as consumed so the same signed URL cannot be
     * replayed. The entry lives as long as the link TTL.
     */
    public function markUnlockTokenUsed(string $signature, int $ttlSeconds): void
    {
        cache()->put($this->unlockTokenKey($signature), true, max(1, $ttlSeconds));
    }

    public function isUnlockTokenUsed(string $signature): bool
    {
        return (bool) cache()->get($this->unlockTokenKey($signature));
    }

    private function unlockTokenKey(string $signature): string
    {
        return 'filament-loginguard:unlock:' . sha1($signature);
    }
}
