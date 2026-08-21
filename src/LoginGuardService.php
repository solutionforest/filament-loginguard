<?php

namespace SolutionForest\FilamentLoginGuard;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Notifications\AccountLockedNotification;

final class LoginGuardService
{
    public function isEnabled(): bool
    {
        return (bool) config('filament-loginguard.enabled', true);
    }

    /**
     * Whitelisted IPs and emails bypass recording AND lockout checks entirely.
     */
    public function isWhitelisted(string $ip, ?string $email): bool
    {
        if (in_array($ip, (array) config('filament-loginguard.whitelisted_ips', []), true)) {
            return true;
        }

        if ($email === null) {
            return false;
        }

        return in_array($email, array_map('strtolower', (array) config('filament-loginguard.whitelisted_emails', [])), true);
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
        $maxAttempts = (int) config('filament-loginguard.max_attempts', 10);
        $windowMinutes = (int) config('filament-loginguard.attempts_window_minutes', 30);
        $trackIp = (bool) config('filament-loginguard.tracking.per_ip', true);
        $trackEmail = (bool) config('filament-loginguard.tracking.per_email', true);

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
        $baseMinutes = (int) config('filament-loginguard.lockout_minutes', 15);

        if ($lockoutCount <= 1) {
            return $baseMinutes;
        }

        $banHours = (array) config('filament-loginguard.ban_hours', []);

        if ($banHours === []) {
            return $baseMinutes;
        }

        $index = min($lockoutCount - 2, count($banHours) - 1);

        return (int) $banHours[$index] * 60;
    }

    /**
     * Successful login: clear counters and any lock for that IP and that email.
     */
    public function resetForSuccess(string $ip, ?string $email): void
    {
        if (! $this->isEnabled()) {
            return;
        }

        LoginAttempt::query()
            ->where(function (Builder $query) use ($ip, $email): void {
                $query->where('ip', $ip);

                if (filled($email)) {
                    $query->orWhere('email', $email);
                }
            })
            ->update([
                'attempts' => 0,
                'lockout_count' => 0,
                'locked_until' => null,
                'last_attempt_at' => null,
            ]);
    }

    /**
     * Send the admin notification, throttled per-IP via the cache. Returns whether it was sent.
     */
    public function notifyLockout(string $ip, string $email, int $minutes): bool
    {
        if (! (bool) config('filament-loginguard.notifications.enabled', true)) {
            return false;
        }

        $recipients = (array) config('filament-loginguard.notifications.mail.to', []);

        if ($recipients === []) {
            return false;
        }

        $cooldownMinutes = (int) config('filament-loginguard.notifications.mail.cooldown_minutes', 60);
        $cacheKey = 'filament-loginguard:notified:' . $ip;

        if ($cooldownMinutes > 0 && cache()->has($cacheKey)) {
            return false;
        }

        cache()->put($cacheKey, true, $cooldownMinutes * 60);

        $notification = new AccountLockedNotification(ip: $ip, email: $email, minutes: $minutes);

        $queue = config('filament-loginguard.notifications.mail.queue', false);

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
        $trackIp = (bool) config('filament-loginguard.tracking.per_ip', true);
        $trackEmail = (bool) config('filament-loginguard.tracking.per_email', true);

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
