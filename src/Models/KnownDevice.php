<?php

namespace SolutionForest\FilamentLoginGuard\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A browser+platform fingerprint first seen for a user, used to flag
 * new-device sessions.
 *
 * @property int $id
 * @property int $user_id
 * @property string $fingerprint
 * @property Carbon $first_seen_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
class KnownDevice extends Model
{
    protected $table = 'filament_loginguard_known_devices';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'user_id' => 'integer',
            'first_seen_at' => 'datetime',
        ];
    }
}
