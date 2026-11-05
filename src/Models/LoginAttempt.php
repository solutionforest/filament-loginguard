<?php

namespace SolutionForest\FilamentLoginGuard\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Support\Carbon;
use SolutionForest\FilamentLoginGuard\Support\ParsesUserAgent;

/**
 * @property int $id
 * @property string $ip
 * @property string $email
 * @property string|null $user_agent
 * @property int $attempts
 * @property int $lockout_count
 * @property int $success_count
 * @property Carbon|null $locked_until
 * @property Carbon|null $last_attempt_at
 * @property Carbon|null $last_success_at
 * @property Carbon|null $window_started_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 * @property-read string|null $device_name
 */
class LoginAttempt extends Model
{
    use HasFactory;
    use ParsesUserAgent;

    protected $table = 'filament_loginguard_attempts';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'attempts' => 'integer',
            'lockout_count' => 'integer',
            'success_count' => 'integer',
            'locked_until' => 'datetime',
            'last_attempt_at' => 'datetime',
            'last_success_at' => 'datetime',
            'window_started_at' => 'datetime',
        ];
    }

    public function isLocked(): bool
    {
        // The current lock state lives in LoginGuardLock (scoped per IP/email);
        // this legacy accessor reports the old per-row column. Kept for
        // backwards compatibility with third-party code.
        return $this->locked_until !== null && $this->locked_until->isFuture();
    }

    public function unlock(): void
    {
        $this->forceFill([
            'attempts' => 0,
            'lockout_count' => 0,
            'locked_until' => null,
            'last_attempt_at' => null,
        ])->save();
    }

    public function scopeLocked(Builder $query): Builder
    {
        return $query->where('locked_until', '>', now());
    }

    /**
     * The most recent security event carrying location metadata for this IP.
     * Powers the "country" badge on the admin attempts table; the of-many
     * subquery lets the table eager-load it in one query (no N+1).
     */
    public function latestLocatedEvent(): HasOne
    {
        return $this->hasOne(SecurityEvent::class, 'ip', 'ip')
            ->ofMany(['id' => 'max'], function (Builder $query): void {
                $query->whereNotNull('metadata');
            });
    }
}
