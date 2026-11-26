<?php

use Illuminate\Support\Facades\Storage;
use SolutionForest\FilamentLoginGuard\Services\IpIntelligence;
use SolutionForest\FilamentLoginGuard\Services\MaxmindIpIntelligence;

it('binds IpIntelligence to the MaxMind implementation', function () {
    expect(app(IpIntelligence::class))->toBeInstanceOf(MaxmindIpIntelligence::class);
});

it('returns null when disabled even with a database available', function () {
    config()->set('filament-loginguard.ip_intel.enabled', false);
    config()->set('filament-loginguard.ip_intel.databases.city', __DIR__ . '/Fixtures/MaxMind/GeoLite2-City-Test.mmdb');

    expect(app(IpIntelligence::class)->lookup('89.160.20.113'))->toBeNull();
});

it('returns null when enabled but no database is configured', function () {
    config()->set('filament-loginguard.ip_intel.enabled', true);
    config()->set('filament-loginguard.ip_intel.databases.country', null);
    config()->set('filament-loginguard.ip_intel.databases.city', null);
    config()->set('filament-loginguard.ip_intel.databases.asn', null);

    expect(app(IpIntelligence::class)->lookup('8.8.8.8'))->toBeNull();
});

it('returns null when the configured database file does not exist', function () {
    config()->set('filament-loginguard.ip_intel.enabled', true);
    config()->set('filament-loginguard.ip_intel.databases.country', '/nonexistent/GeoLite2-Country.mmdb');

    expect(app(IpIntelligence::class)->lookup('8.8.8.8'))->toBeNull();
});

it('returns null for an empty IP address', function () {
    config()->set('filament-loginguard.ip_intel.enabled', true);

    expect(app(IpIntelligence::class)->lookup(''))->toBeNull();
});

it('reads GeoLite2 databases and combines city precision with ASN details', function () {
    config()->set('filament-loginguard.ip_intel.enabled', true);
    config()->set('filament-loginguard.ip_intel.databases', [
        'city' => __DIR__ . '/Fixtures/MaxMind/GeoLite2-City-Test.mmdb',
        'country' => __DIR__ . '/Fixtures/MaxMind/GeoLite2-Country-Test.mmdb',
        'asn' => __DIR__ . '/Fixtures/MaxMind/GeoLite2-ASN-Test.mmdb',
    ]);

    $intel = app(IpIntelligence::class);

    expect($intel->lookup(' ::ffff:89.160.20.113 ')?->toArray())->toBe([
        'country' => 'SE',
        'country_name' => 'Sweden',
        'city' => 'Linköping',
        'subdivision' => 'Östergötland County',
        'latitude' => 58.4167,
        'longitude' => 15.6167,
        'accuracy_radius_km' => 76,
        'asn' => 29518,
        'asn_organization' => 'Bredband2 AB',
    ])->and($intel->lookup('192.0.2.1'))->toBeNull()
        ->and($intel->lookup('invalid-ip'))->toBeNull();
});

it('keeps coordinates when the city database record has no city or country', function () {
    config()->set('filament-loginguard.ip_intel.enabled', true);
    config()->set('filament-loginguard.ip_intel.databases.city', __DIR__ . '/Fixtures/MaxMind/GeoLite2-City-Test.mmdb');

    expect(app(IpIntelligence::class)->lookup('2A02:D500:0:0:0:0:0:1')?->toArray())->toBe([
        'country' => null,
        'country_name' => null,
        'city' => null,
        'subdivision' => null,
        'latitude' => 48.69096,
        'longitude' => 9.14062,
        'accuracy_radius_km' => 100,
        'asn' => null,
        'asn_organization' => null,
    ]);
});

it('returns ASN signals when only the ASN database is configured', function () {
    config()->set('filament-loginguard.ip_intel.enabled', true);
    config()->set('filament-loginguard.ip_intel.databases.asn', __DIR__ . '/Fixtures/MaxMind/GeoLite2-ASN-Test.mmdb');

    expect(app(IpIntelligence::class)->lookup('1.0.0.1')?->toArray())->toBe([
        'country' => null,
        'country_name' => null,
        'city' => null,
        'subdivision' => null,
        'latitude' => null,
        'longitude' => null,
        'accuracy_radius_km' => null,
        'asn' => 15169,
        'asn_organization' => 'Google Inc.',
    ]);
});

it('falls back to readable databases if the city file is corrupt', function () {
    $disk = Storage::fake('geoip-test');
    $disk->put('broken.mmdb', 'Invalid MaxMind file contents');

    config()->set('filament-loginguard.ip_intel.enabled', true);
    config()->set('filament-loginguard.ip_intel.databases', [
        'city' => $disk->path('broken.mmdb'),
        'country' => __DIR__ . '/Fixtures/MaxMind/GeoLite2-Country-Test.mmdb',
        'asn' => __DIR__ . '/Fixtures/MaxMind/GeoLite2-ASN-Test.mmdb',
    ]);

    expect(app(IpIntelligence::class)->lookup('216.160.83.57')?->toArray())->toBe([
        'country' => 'US',
        'country_name' => 'United States',
        'city' => null,
        'subdivision' => null,
        'latitude' => null,
        'longitude' => null,
        'accuracy_radius_km' => null,
        'asn' => 209,
        'asn_organization' => null,
    ]);
});

it('returns null if the only configured database is corrupt', function () {
    $disk = Storage::fake('geoip-test');
    $disk->put('broken.mmdb', 'Invalid MaxMind file contents');

    config()->set('filament-loginguard.ip_intel.enabled', true);
    config()->set('filament-loginguard.ip_intel.databases.country', $disk->path('broken.mmdb'));

    expect(app(IpIntelligence::class)->lookup('89.160.20.113'))->toBeNull();
});
