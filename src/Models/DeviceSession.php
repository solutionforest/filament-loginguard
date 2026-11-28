<?php

namespace SolutionForest\FilamentLoginGuard\Models;

use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use SolutionForest\FilamentLoginGuard\Support\SessionDriver;

/**
 * Maps a device identity to a Laravel session row (sessions stay untouched;
 * the mapping lives in our own table).
 *
 * @property int $id
 * @property int $device_id
 * @property string $session_id
 * @property string $guard
 * @property Carbon $last_seen_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
class DeviceSession extends Model
{
    protected $table = 'filament_loginguard_device_sessions';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'last_seen_at' => 'datetime',
        ];
    }

    public static function liveSessionIds(): Builder
    {
        return DB::table(filament_loginguard_config_string('filament-loginguard.sessions.table', 'sessions'))
            ->select('id')
            ->where('last_activity', '>=', SessionDriver::lifetimeCutoff()->getTimestamp());
    }

    /**
     * Restrict mappings to live sessions — the single liveness rule shared by
     * the My Devices page, forget, the device cap and cleanup.
     *
     * Database driver: the mapped session row exists and is fresh. Other
     * drivers (redis/valkey/file/array/cookie) cannot be queried, so a mapping
     * is live while its `last_seen_at` is within `session.lifetime`.
     *
     * @param  EloquentBuilder<DeviceSession>  $query
     * @return EloquentBuilder<DeviceSession>
     */
    public static function constrainLive(EloquentBuilder $query): EloquentBuilder
    {
        if (SessionDriver::usesDatabase()) {
            $query->whereIn('session_id', self::liveSessionIds());
        } else {
            $query->where('last_seen_at', '>=', SessionDriver::lifetimeCutoff());
        }

        return $query;
    }

    /**
     * Restrict mappings to stale ones (the complement of constrainLive()).
     *
     * @param  EloquentBuilder<DeviceSession>  $query
     * @return EloquentBuilder<DeviceSession>
     */
    public static function constrainStale(EloquentBuilder $query): EloquentBuilder
    {
        if (SessionDriver::usesDatabase()) {
            $query->whereNotIn('session_id', self::liveSessionIds());
        } else {
            $query->where('last_seen_at', '<', SessionDriver::lifetimeCutoff());
        }

        return $query;
    }

    /**
     * @return BelongsTo<Device, $this>
     */
    public function device(): BelongsTo
    {
        return $this->belongsTo(Device::class, 'device_id');
    }
}
