<?php

namespace SolutionForest\FilamentLoginGuard\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

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
            ->where('last_activity', '>=', now()->subMinutes(filament_loginguard_config_int('session.lifetime', 120))->timestamp);
    }

    /**
     * @return BelongsTo<Device, $this>
     */
    public function device(): BelongsTo
    {
        return $this->belongsTo(Device::class, 'device_id');
    }
}
