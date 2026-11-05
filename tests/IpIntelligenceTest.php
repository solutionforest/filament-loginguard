<?php

use SolutionForest\FilamentLoginGuard\Services\IpIntelligence;
use SolutionForest\FilamentLoginGuard\Services\MaxmindIpIntelligence;

it('binds IpIntelligence to the MaxMind implementation', function () {
    expect(app(IpIntelligence::class))->toBeInstanceOf(MaxmindIpIntelligence::class);
});

it('returns null when disabled', function () {
    config()->set('filament-loginguard.ip_intel.enabled', false);

    expect(app(IpIntelligence::class)->lookup('8.8.8.8'))->toBeNull();
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
