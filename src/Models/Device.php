<?php

namespace SolutionForest\FilamentLoginGuard\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;

/**
 * A device identity bound to one account (guard + user) via an opaque cookie
 * token. The database only ever holds the SHA-256 hash of the token.
 *
 * `trusted_at` is reserved for a future step-up verification flow; a
 * successful password login alone only ever means "recognized".
 *
 * @property int $id
 * @property string $guard
 * @property string $user_type
 * @property string $user_identifier
 * @property string $token_hash
 * @property string|null $device_name
 * @property string|null $user_agent
 * @property string|null $first_ip
 * @property string|null $last_ip
 * @property Carbon $first_seen_at
 * @property Carbon $last_seen_at
 * @property Carbon|null $trusted_at
 * @property Carbon|null $revoked_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
class Device extends Model
{
    protected $table = 'filament_loginguard_devices';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'first_seen_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'trusted_at' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }

    /**
     * Whether the device has at least one live session.
     */
    public function hasActiveSessions(): bool
    {
        return $this->sessions()
            ->whereIn('session_id', function ($query): void {
                $query->select('id')
                    ->from(config('filament-loginguard.sessions.table', 'sessions'))
                    ->whereRaw('last_activity >= ?', [now()->subMinutes((int) config('session.lifetime', 120))->getTimestamp()]);
            })
            ->exists();
    }

    public function sessions(): HasMany
    {
        return $this->hasMany(DeviceSession::class, 'device_id');
    }
}
