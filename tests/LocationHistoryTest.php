<?php

use SolutionForest\FilamentLoginGuard\Models\LocationHistory;

it('records a location and flags novel countries and ASNs', function () {
    LocationHistory::record('web', 'App\\Models\\User', '1', 'US', 13335);

    expect(LocationHistory::isNewCountry('web', 'App\\Models\\User', '1', 'US'))->toBeFalse()
        ->and(LocationHistory::isNewCountry('web', 'App\\Models\\User', '1', 'GB'))->toBeTrue()
        ->and(LocationHistory::isNewAsn('web', 'App\\Models\\User', '1', 13335))->toBeFalse()
        ->and(LocationHistory::isNewAsn('web', 'App\\Models\\User', '1', 15169))->toBeTrue();
});

it('bumps last_seen_at instead of duplicating rows on repeat logins', function () {
    LocationHistory::record('web', 'App\\Models\\User', '1', 'US', 13335);
    LocationHistory::record('web', 'App\\Models\\User', '1', 'US', 13335);

    expect(LocationHistory::query()->count())->toBe(1);
});

it('treats a country as new again after the novelty window', function () {
    LocationHistory::record('web', 'App\\Models\\User', '1', 'US', null);

    LocationHistory::query()->first()->forceFill(['last_seen_at' => now()->subDays(120)])->save();

    expect(LocationHistory::isNewCountry('web', 'App\\Models\\User', '1', 'US'))->toBeTrue();
});

it('records nothing when both country and asn are null', function () {
    LocationHistory::record('web', 'App\\Models\\User', '1', null, null);

    expect(LocationHistory::query()->count())->toBe(0);
});

it('never flags a null signal as new', function () {
    expect(LocationHistory::isNewCountry('web', 'App\\Models\\User', '1', null))->toBeFalse()
        ->and(LocationHistory::isNewAsn('web', 'App\\Models\\User', '1', null))->toBeFalse();
});
