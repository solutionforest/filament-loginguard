<?php

namespace SolutionForest\FilamentLoginGuard;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use SolutionForest\FilamentLoginGuard\Models\KnownDevice;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Models\UserSession;
use SolutionForest\FilamentLoginGuard\Notifications\AccountLockedNotification;
use SolutionForest\FilamentLoginGuard\Notifications\NewDeviceLoginNotification;
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
        if (in_array($ip, (array) config('filament-loginguard.lockout.whitelist.ips', []), true)) {
            return true;
        }

        if ($email === null) {
            return false;
        }

        return in_array($email, array_map('strtolower', (array) config('filament-loginguard.lockout.whitelist.emails', [])), true);
    }

    public function isLocked(string $ip, ?string $email): bool
    {
        if (! $this->isEnabled()) {
            return false;
        }

        return $this->matchingRowsQuery($ip, $email)
            ->where('locked_until', '>', now())
            ->exists();
    }

    public function remainingLockSeconds(string $ip, ?string $email): int
    {
        $lockedUntil = $this->matchingRowsQuery($ip, $email)
            ->where('locked_until', '>', now())
            ->max('locked_until');

        return $lockedUntil ? (int) now()->diffInSeconds($lockedUntil) : 0;
    }

    /**
     * Record one failed attempt. Returns a LockoutResult describing whether THIS attempt
     * triggered a lockout (so the listener can throw + notify).
     */
    public function recordFailure(string $ip, string $email, ?string $userAgent = null): LockoutResult
    {
        $now = Carbon::now();
        $maxAttempts = (int) config('filament-loginguard.lockout.max_attempts', 10);
        $windowMinutes = (int) config('filament-loginguard.lockout.attempts_window_minutes', 30);
        $trackIp = (bool) config('filament-loginguard.lockout.tracking.per_ip', true);
        $trackEmail = (bool) config('filament-loginguard.lockout.tracking.per_email', true);

        /** @var LoginAttempt $row */
        $row = LoginAttempt::query()->firstOrCreate(['ip' => $ip, 'email' => $email]);

        // Attempt decay: a stale row starts counting from zero again (lockout_count is kept:
        // escalation history is permanent until a success/unblock resets it).
        if ($row->last_attempt_at !== null && $row->last_attempt_at->lt($now->copy()->subMinutes($windowMinutes))) {
            $row->attempts = 0;
        }

        $row->attempts += 1;
        $row->last_attempt_at = $now;
        $row->user_agent = $userAgent === null ? null : Str::limit($userAgent, 255);
        $row->save();

        $cutoff = $now->copy()->subMinutes($windowMinutes);

        // Aggregate sums count attempts of all rows of the same IP (or same email)
        // that are still inside the window.
        $lockIds = [];

        if ($trackIp) {
            $ipAttempts = (int) LoginAttempt::query()
                ->where('ip', $ip)
                ->where('last_attempt_at', '>=', $cutoff)
                ->sum('attempts');

            if ($ipAttempts >= $maxAttempts) {
                $lockIds = array_merge($lockIds, LoginAttempt::query()->where('ip', $ip)->pluck('id')->all());
            }
        }

        if ($trackEmail) {
            $emailAttempts = (int) LoginAttempt::query()
                ->where('email', $email)
                ->where('last_attempt_at', '>=', $cutoff)
                ->sum('attempts');

            if ($emailAttempts >= $maxAttempts) {
                $lockIds = array_merge($lockIds, LoginAttempt::query()->where('email', $email)->pluck('id')->all());
            }
        }

        if (! $trackIp && ! $trackEmail && $row->attempts >= $maxAttempts) {
            $lockIds[] = $row->getKey();
        }

        if ($lockIds === []) {
            return new LockoutResult(locked: false);
        }

        // Apply the lock with escalation. Never shorten an existing lock; only bump
        // lockout_count when the lock is actually (re)applied with a longer duration.
        $locked = false;

        LoginAttempt::query()
            ->whereKey(array_unique($lockIds))
            ->get()
            ->each(function (LoginAttempt $target) use ($now, &$locked): void {
                $newCount = $target->lockout_count + 1;
                $lockedUntil = $now->copy()->addMinutes($this->durationForLockoutCount($newCount));

                if ($target->locked_until !== null && $target->locked_until->gte($lockedUntil)) {
                    return;
                }

                $target->lockout_count = $newCount;
                $target->locked_until = $lockedUntil;
                $target->save();

                $locked = true;
            });

        if (! $locked) {
            return new LockoutResult(locked: false);
        }

        // The recorded row always belongs to the lock set (its own IP/email triggered it).
        $fresh = LoginAttempt::query()->find($row->getKey());
        $seconds = ($fresh !== null && $fresh->locked_until !== null)
            ? (int) $now->diffInSeconds($fresh->locked_until)
            : 0;
        $seconds = max(0, $seconds);

        return new LockoutResult(
            locked: true,
            secondsRemaining: $seconds,
            minutes: (int) ceil($seconds / 60),
        );
    }

    /**
     * First lockout = lockout_minutes; 2nd = ban_hours[0]; 3rd = ban_hours[1]; ... last entry repeats.
     */
    public function durationForLockoutCount(int $lockoutCount): int
    {
        $baseMinutes = (int) config('filament-loginguard.lockout.lockout_minutes', 15);

        if ($lockoutCount <= 1) {
            return $baseMinutes;
        }

        $banHours = (array) config('filament-loginguard.lockout.ban_hours', []);

        if ($banHours === []) {
            return $baseMinutes;
        }

        $index = min($lockoutCount - 2, count($banHours) - 1);

        return (int) $banHours[$index] * 60;
    }

    /**
     * Successful login: clear counters and any lock for this specific (ip, email) row.
     *
     * The row is keyed on the (ip, email) pair, so a successful login must only reset
     * that one pair. Matching by IP alone (or by IP *or* email) would wipe the failed
     * attempts of every other account sharing the IP — e.g. every account behind a NAT,
     * or every local account on 127.0.0.1.
     */
    public function resetForSuccess(string $ip, ?string $email): void
    {
        if (! $this->isEnabled()) {
            return;
        }

        $query = LoginAttempt::query()->where('ip', $ip);

        if (filled($email)) {
            $query->where('email', $email);
        }

        $query->update([
            'attempts' => 0,
            'lockout_count' => 0,
            'locked_until' => null,
            'last_attempt_at' => null,
        ]);
    }

    /**
     * Record a successful login: stamp the success counter and clear the failed
     * attempts / lockout state for this (ip, email) row.
     */
    public function recordSuccess(string $ip, string $email): void
    {
        if (! $this->isEnabled()) {
            return;
        }

        /** @var LoginAttempt $row */
        $row = LoginAttempt::query()->firstOrCreate(['ip' => $ip, 'email' => $email]);

        $row->forceFill([
            'attempts' => 0,
            'lockout_count' => 0,
            'locked_until' => null,
            'last_attempt_at' => null,
            'success_count' => (int) $row->success_count + 1,
            'last_success_at' => Carbon::now(),
        ])->save();
    }

    /**
     * Record the browser+platform fingerprint for a user on login. When the device
     * is seen for the first time, notify the configured recipients (if any).
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

        if ($device->wasRecentlyCreated) {
            $this->notifyNewDevice($fingerprint, $email ?? (string) $userId);
        }
    }

    /**
     * Evict the oldest sessions beyond the per-user concurrent limit, making room
     * for the session that is being created right now.
     */
    public function enforceConcurrentLimit(int $userId): void
    {
        $limit = (int) config('filament-loginguard.sessions.concurrent_limit', 0);

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
     * Send the new-device notification to the configured recipients.
     */
    private function notifyNewDevice(string $fingerprint, string $email): void
    {
        if (! (bool) config('filament-loginguard.sessions.new_device.notification.enabled', false)) {
            return;
        }

        $recipients = (array) config('filament-loginguard.sessions.new_device.notification.to', []);

        if ($recipients === []) {
            return;
        }

        $notification = new NewDeviceLoginNotification(
            email: $email,
            device: $fingerprint,
            ip: (string) request()->ip(),
        );

        $queue = config('filament-loginguard.sessions.new_device.notification.queue', false);

        foreach ($recipients as $recipient) {
            $notifiable = Notification::route('mail', $recipient);

            if ($queue !== false) {
                $notifiable->notify($notification->onQueue((string) $queue));
            } else {
                $notifiable->notifyNow($notification);
            }
        }
    }

    /**
     * Send the admin notification, throttled per-IP via the cache. Returns whether it was sent.
     */
    public function notifyLockout(string $ip, string $email, int $minutes): bool
    {
        if (! (bool) config('filament-loginguard.lockout.notifications.enabled', true)) {
            return false;
        }

        $recipients = (array) config('filament-loginguard.lockout.notifications.mail.to', []);

        if ($recipients === []) {
            return false;
        }

        $cooldownMinutes = (int) config('filament-loginguard.lockout.notifications.mail.cooldown_minutes', 60);
        $cacheKey = 'filament-loginguard:notified:' . $ip;

        if ($cooldownMinutes > 0 && cache()->has($cacheKey)) {
            return false;
        }

        cache()->put($cacheKey, true, $cooldownMinutes * 60);

        $notification = new AccountLockedNotification(ip: $ip, email: $email, minutes: $minutes);

        $queue = config('filament-loginguard.lockout.notifications.mail.queue', false);

        foreach ($recipients as $recipient) {
            $notifiable = Notification::route('mail', $recipient);

            if ($queue !== false) {
                $notifiable->notify($notification->onQueue((string) $queue));
            } else {
                $notifiable->notifyNow($notification);
            }
        }

        return true;
    }

    /**
     * Rows that "represent" the given IP/email according to the tracking toggles.
     */
    private function matchingRowsQuery(string $ip, ?string $email): Builder
    {
        $trackIp = (bool) config('filament-loginguard.lockout.tracking.per_ip', true);
        $trackEmail = (bool) config('filament-loginguard.lockout.tracking.per_email', true);

        return LoginAttempt::query()->where(function (Builder $query) use ($ip, $email, $trackIp, $trackEmail): void {
            // Per-pair semantics when both aggregates are off: only the exact (ip, email) row counts.
            if (! $trackIp && ! $trackEmail) {
                $query->where('ip', $ip)->where('email', $email ?? '');

                return;
            }

            if ($trackIp) {
                $query->orWhere('ip', $ip);
            }

            if ($trackEmail && filled($email)) {
                $query->orWhere('email', $email);
            }
        });
    }
}
