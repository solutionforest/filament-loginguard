<?php

namespace SolutionForest\FilamentLoginGuard\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use SolutionForest\FilamentLoginGuard\Support\ParsesUserAgent;

/**
 * A row of Laravel's `sessions` table (requires SESSION_DRIVER=database).
 *
 * @property string $id
 * @property int|null $user_id
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property string $payload
 * @property int $last_activity
 * @property-read string|null $device_name
 * @property-read string|null $user_email
 * @property-read Carbon $last_active_at
 * @property-read bool $is_online
 * @property-read string $last_active_label
 */
class UserSession extends Model
{
    use ParsesUserAgent;

    protected $table = 'sessions';

    protected $primaryKey = 'id';

    public $incrementing = false;

    protected $keyType = 'string';

    public $timestamps = false;

    protected $guarded = [];

    public function __construct(array $attributes = [])
    {
        $this->table = (string) config('filament-loginguard.sessions.table', 'sessions');

        parent::__construct($attributes);
    }

    public function getUserEmailAttribute(): ?string
    {
        if ($this->user_id === null) {
            return null;
        }

        $model = config('filament-loginguard.sessions.user_model') ?? config('auth.providers.users.model');

        if (! is_string($model) || ! class_exists($model)) {
            return null;
        }

        return $model::query()->find($this->user_id)?->email;
    }

    public function getLastActiveAtAttribute(): Carbon
    {
        return Carbon::createFromTimestamp((int) ($this->attributes['last_activity'] ?? 0));
    }

    public function getIsOnlineAttribute(): bool
    {
        $threshold = (int) config('filament-loginguard.sessions.online_threshold_minutes', 5);

        return $this->last_active_at->gte(now()->subMinutes($threshold));
    }

    public function getLastActiveLabelAttribute(): string
    {
        return $this->is_online
            ? (string) __('filament-loginguard::loginguard.sessions.table.online_now')
            : $this->last_active_at->diffForHumans();
    }
}
