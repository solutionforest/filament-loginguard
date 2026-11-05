<?php

namespace SolutionForest\FilamentLoginGuard\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Compact projection of the distinct countries / ASNs an account has signed
 * in from — powers the "new country / new ASN" signals. One row per
 * (guard, user_type, user_identifier, country, asn) combination; `last_seen_at`
 * is bumped on each matching login.
 *
 * Keyed by string `user_identifier` on purpose: supports integer ids, UUIDs and
 * ULIDs without schema changes, and `user_type` namespaces different user models
 * so `web` user #1 and `admin` user #1 never collide.
 *
 * @property int $id
 * @property string $guard
 * @property string $user_type
 * @property string $user_identifier
 * @property string|null $country
 * @property int|null $asn
 * @property Carbon $first_seen_at
 * @property Carbon $last_seen_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
class LocationHistory extends Model
{
    protected $table = 'filament_loginguard_location_history';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'asn' => 'integer',
            'first_seen_at' => 'datetime',
            'last_seen_at' => 'datetime',
        ];
    }

    /**
     * Record (or bump) a login's location for an account. Best-effort: never
     * throws, because this runs inside the login flow.
     */
    public static function record(string $guard, string $userType, string $userIdentifier, ?string $country, ?int $asn): void
    {
        if ($country === null && $asn === null) {
            return; // nothing meaningful to record
        }

        $now = Carbon::now();

        try {
            $query = static::query()
                ->where('guard', $guard)
                ->where('user_type', $userType)
                ->where('user_identifier', $userIdentifier);

            if ($country === null) {
                $query->whereNull('country');
            } else {
                $query->where('country', $country);
            }

            if ($asn === null) {
                $query->whereNull('asn');
            } else {
                $query->where('asn', $asn);
            }

            $existing = $query->first();

            if ($existing !== null) {
                $existing->forceFill([
                    'first_seen_at' => $existing->first_seen_at ?? $now,
                    'last_seen_at' => $now,
                ])->save();

                return;
            }

            static::query()->create([
                'guard' => $guard,
                'user_type' => $userType,
                'user_identifier' => $userIdentifier,
                'country' => $country,
                'asn' => $asn,
                'first_seen_at' => $now,
                'last_seen_at' => $now,
            ]);
        } catch (\Throwable) {
            // Best-effort: never break authentication over location history.
        }
    }

    /**
     * Whether this country is "new" for the account: not seen within the
     * novelty window. A null country is never "new" (no signal to flag).
     */
    public static function isNewCountry(string $guard, string $userType, string $userIdentifier, ?string $country): bool
    {
        if ($country === null) {
            return false;
        }

        return ! static::query()
            ->where('guard', $guard)
            ->where('user_type', $userType)
            ->where('user_identifier', $userIdentifier)
            ->where('country', $country)
            ->where('last_seen_at', '>=', self::noveltyCutoff())
            ->exists();
    }

    /**
     * Whether this ASN is "new" for the account. A null ASN is never "new".
     */
    public static function isNewAsn(string $guard, string $userType, string $userIdentifier, ?int $asn): bool
    {
        if ($asn === null) {
            return false;
        }

        return ! static::query()
            ->where('guard', $guard)
            ->where('user_type', $userType)
            ->where('user_identifier', $userIdentifier)
            ->where('asn', $asn)
            ->where('last_seen_at', '>=', self::noveltyCutoff())
            ->exists();
    }

    private static function noveltyCutoff(): Carbon
    {
        return Carbon::now()->subDays((int) config('filament-loginguard.ip_intel.novelty_window_days', 90));
    }
}
