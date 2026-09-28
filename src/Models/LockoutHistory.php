<?php

namespace SolutionForest\FilamentLoginGuard\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Append-only escalation history. Every applied lockout is recorded here so the
 * attempts cleanup command can delete stale attempt rows without resetting the
 * escalation ladder — the next `lockout_count` is derived from the number of
 * history entries for the (ip, email) pair, not from the deletable attempt row.
 *
 * @property int $id
 * @property string $ip
 * @property string $email
 * @property Carbon $locked_at
 * @property Carbon $locked_until
 * @property int $lockout_count
 * @property int $duration_minutes
 * @property string|null $triggered_by_ip
 * @property string|null $triggered_by_email
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
class LockoutHistory extends Model
{
    protected $table = 'filament_loginguard_lockout_histories';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'locked_at' => 'datetime',
            'locked_until' => 'datetime',
            'lockout_count' => 'integer',
            'duration_minutes' => 'integer',
        ];
    }
}
