<?php

namespace SolutionForest\FilamentLoginGuard\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Append-only security event log — the source of truth for the charts and the
 * 24h stats widget.
 *
 * Counters and lock state (LoginAttempt / LoginGuardLock) describe *the current
 * moment* and get reset, decayed or cleaned up; this log preserves *what
 * happened*, so trends and leaderboards stay accurate across windows and
 * cleanups. `LockoutHistory` rows are mirrored here as `lockout_started`
 * events (the audit trail stays in both places for now).
 *
 * @property int $id
 * @property string $type login_failed | login_succeeded | lockout_started | unlocked
 * @property string|null $ip
 * @property string|null $email
 * @property int|null $user_id
 * @property string|null $guard
 * @property string|null $device
 * @property Carbon $occurred_at
 * @property array|null $metadata
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
class SecurityEvent extends Model
{
    public const TYPE_LOGIN_FAILED = 'login_failed';

    public const TYPE_LOGIN_SUCCEEDED = 'login_succeeded';

    public const TYPE_LOCKOUT_STARTED = 'lockout_started';

    public const TYPE_UNLOCKED = 'unlocked';

    public const TYPE_DEVICE_REGISTERED = 'device_registered';

    public const TYPE_DEVICE_SEEN = 'device_seen';

    public const TYPE_DEVICE_FORGOTTEN = 'device_forgotten';

    public const TYPE_DEVICE_REVOKED = 'device_revoked';

    public const TYPE_SESSION_REVOKED_BY_USER = 'session_revoked_by_user';

    public const TYPE_SESSIONS_REVOKED_OTHERS = 'sessions_revoked_others';

    protected $table = 'filament_loginguard_events';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'occurred_at' => 'datetime',
            'metadata' => 'array',
        ];
    }

    /**
     * Persist an event in one call; never throws — security logging must not
     * break the login flow.
     */
    public static function record(string $type, ?string $ip, ?string $email, ?int $userId = null, ?string $guard = null, ?string $device = null, ?array $metadata = null): void
    {
        try {
            self::query()->create([
                'type' => $type,
                'ip' => $ip,
                'email' => $email,
                'user_id' => $userId,
                'guard' => $guard,
                'device' => $device,
                'occurred_at' => Carbon::now(),
                'metadata' => $metadata,
            ]);
        } catch (\Throwable) {
            // The event log is best-effort: never break authentication over it.
        }
    }
}
