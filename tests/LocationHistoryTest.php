<?php

use Carbon\Carbon;
use SolutionForest\FilamentLoginGuard\Models\LocationHistory;

beforeEach(function () {
    Carbon::setTestNow('2026-01-15 12:00:00');
});

afterEach(function () {
    Carbon::setTestNow(null);
});

it('records a location and flags novel countries and ASNs', function () {
    LocationHistory::record('web', 'App\\Models\\User', '1', 'US', 13335);

    expect(LocationHistory::isNewCountry('web', 'App\\Models\\User', '1', 'US'))->toBeFalse()
        ->and(LocationHistory::isNewCountry('web', 'App\\Models\\User', '1', 'GB'))->toBeTrue()
        ->and(LocationHistory::isNewAsn('web', 'App\\Models\\User', '1', 13335))->toBeFalse()
        ->and(LocationHistory::isNewAsn('web', 'App\\Models\\User', '1', 15169))->toBeTrue();
});

it('bumps last_seen_at instead of duplicating rows on repeat logins', function () {
    // Both null combinations must match their earlier row when revisited.
    LocationHistory::record('web', 'App\\Models\\User', '1', 'US', null);
    LocationHistory::record('web', 'App\\Models\\User', '1', null, 13335);

    Carbon::setTestNow('2026-01-16 13:00:00');
    LocationHistory::record('web', 'App\\Models\\User', '1', 'US', null);
    LocationHistory::record('web', 'App\\Models\\User', '1', null, 13335);

    $history = LocationHistory::query()->orderBy('id')->get();

    expect($history)->toHaveCount(2);

    foreach ($history as $record) {
        expect($record->first_seen_at->toDateTimeString())->toBe('2026-01-15 12:00:00')
            ->and($record->last_seen_at->toDateTimeString())->toBe('2026-01-16 13:00:00');
    }
});

it('isolates location novelty by guard, user model, and account identifier', function () {
    $account = '497939e9-5664-4f44-838f-b7d7ea434a20';
    LocationHistory::record('web', 'App\\Models\\User', $account, 'US', 13335);

    expect(LocationHistory::isNewCountry('web', 'App\\Models\\User', $account, 'US'))->toBeFalse()
        ->and(LocationHistory::isNewAsn('web', 'App\\Models\\User', $account, 13335))->toBeFalse();

    foreach ([
        ['admin', 'App\\Models\\User', $account],
        ['web', 'App\\Models\\Admin', $account],
        ['web', 'App\\Models\\User', '8dbf1480-f099-4ad3-b871-75309ed441b9'],
    ] as [$guard, $model, $identifier]) {
        expect(LocationHistory::isNewCountry($guard, $model, $identifier, 'US'))->toBeTrue()
            ->and(LocationHistory::isNewAsn($guard, $model, $identifier, 13335))->toBeTrue();

        LocationHistory::record($guard, $model, $identifier, 'US', 13335);

        expect(LocationHistory::isNewCountry($guard, $model, $identifier, 'US'))->toBeFalse()
            ->and(LocationHistory::isNewAsn($guard, $model, $identifier, 13335))->toBeFalse();
    }

    expect(LocationHistory::query()->count())->toBe(4);
});

it('includes the novelty cutoff and treats older countries and ASNs as new again', function () {
    config()->set('filament-loginguard.ip_intel.novelty_window_days', 14);

    Carbon::setTestNow('2026-01-01 11:59:59');
    LocationHistory::record('web', 'App\\Models\\User', '1', 'SE', 29518);

    Carbon::setTestNow('2026-01-01 12:00:00');
    LocationHistory::record('web', 'App\\Models\\User', '1', 'US', 13335);

    Carbon::setTestNow('2026-01-15 12:00:00');

    expect(LocationHistory::isNewCountry('web', 'App\\Models\\User', '1', 'SE'))->toBeTrue()
        ->and(LocationHistory::isNewAsn('web', 'App\\Models\\User', '1', 29518))->toBeTrue()
        ->and(LocationHistory::isNewCountry('web', 'App\\Models\\User', '1', 'US'))->toBeFalse()
        ->and(LocationHistory::isNewAsn('web', 'App\\Models\\User', '1', 13335))->toBeFalse();
});

it('records nothing when both country and asn are null', function () {
    LocationHistory::record('web', 'App\\Models\\User', '1', null, null);

    expect(LocationHistory::query()->count())->toBe(0);
});

it('never flags a null signal as new', function () {
    expect(LocationHistory::isNewCountry('web', 'App\\Models\\User', '1', null))->toBeFalse()
        ->and(LocationHistory::isNewAsn('web', 'App\\Models\\User', '1', null))->toBeFalse();
});
