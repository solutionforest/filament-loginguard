<?php

namespace SolutionForest\FilamentLoginGuard\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Current security state, one row per lock scope (a single IP or a single email).
 *
 * Locks are fully independent of the (ip, email) attempt rows: an aggregate IP
 * lock and an email lock are separate rows here, so unlocking one scope never
 * touches the other. This fixes the old model where both locks shared the
 * attempt row's single `locked_until` column and clearing an email lock also
 * cleared the IP lock on the same row.
 *
 * @property int $id
 * @property string $scope_type 'ip' | 'email'
 * @property string $scope_key the IP or the (normalized) email
 * @property Carbon $locked_until
 * @property int $escalation_count
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
class LoginGuardLock extends Model
{
    public const SCOPE_IP = 'ip';

    public const SCOPE_EMAIL = 'email';

    public const SCOPE_PAIR = 'pair';

    protected $table = 'filament_loginguard_locks';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'locked_until' => 'datetime',
            'escalation_count' => 'integer',
        ];
    }

    /**
     * Locks that are still in force.
     *
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->where('locked_until', '>', now());
    }

    /**
     * Convenience for places where the dynamic scope call is not statically
     * resolvable: same constraint as scopeActive().
     */
    public static function activeQuery(): Builder
    {
        return static::query()->where('locked_until', '>', now());
    }
}
