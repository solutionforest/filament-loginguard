<?php

namespace SolutionForest\FilamentLoginGuard\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $ip
 * @property string $email
 * @property string|null $user_agent
 * @property int $attempts
 * @property int $lockout_count
 * @property Carbon|null $locked_until
 * @property Carbon|null $last_attempt_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
class LoginAttempt extends Model
{
    use HasFactory;

    protected $table = 'filament_loginguard_attempts';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'attempts' => 'integer',
            'lockout_count' => 'integer',
            'locked_until' => 'datetime',
            'last_attempt_at' => 'datetime',
        ];
    }

    public function isLocked(): bool
    {
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
}
