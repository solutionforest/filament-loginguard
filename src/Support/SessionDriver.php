<?php

namespace SolutionForest\FilamentLoginGuard\Support;

use Illuminate\Support\Carbon;

/**
 * Session-driver capabilities the device layer depends on. Always read from
 * config at call time so long-lived (Octane) workers follow config changes.
 */
final class SessionDriver
{
    /**
     * Whether sessions live in the database table (`sessions.table`), so their
     * liveness can be checked against `last_activity`.
     */
    public static function usesDatabase(): bool
    {
        return config('session.driver') === 'database';
    }

    /**
     * Whether another browser's session can be destroyed server-side. The
     * cookie driver stores the whole session in the client's cookie, so there
     * is nothing on the server to delete.
     */
    public static function canDestroyOtherSessions(): bool
    {
        return config('session.driver') !== 'cookie';
    }

    /**
     * Sessions idle for longer than `session.lifetime` are expired.
     */
    public static function lifetimeCutoff(): Carbon
    {
        return Carbon::now()->subMinutes(filament_loginguard_config_int('session.lifetime', 120));
    }
}
