<?php

use SolutionForest\FilamentLoginGuard\IpLocation;
use SolutionForest\FilamentLoginGuard\Services\IpIntelligence;

it('reports the setup and fails when no result can be resolved', function () {
    config()->set('filament-loginguard.ip_intel.enabled', false);
    config()->set('filament-loginguard.ip_intel.databases.country', null);
    config()->set('filament-loginguard.ip_intel.databases.city', null);
    config()->set('filament-loginguard.ip_intel.databases.asn', null);

    $this->artisan('filament-loginguard:ip-intel:test')
        ->expectsOutputToContain('Enabled: no')
        ->expectsOutputToContain('geoip2/geoip2 package: installed')
        ->expectsOutputToContain('country: not configured / file missing')
        ->assertExitCode(1);
});

it('prints the resolved signals for a successful lookup', function () {
    app()->instance(IpIntelligence::class, new class implements IpIntelligence
    {
        public function lookup(string $ip): ?IpLocation
        {
            return new IpLocation(
                country: 'US',
                countryName: 'United States',
                city: 'Minneapolis',
                subdivision: 'Minnesota',
                latitude: 44.9733,
                longitude: -93.2323,
                accuracyRadiusKm: 20,
                asn: 7922,
                asnOrganization: 'Comcast',
            );
        }
    });

    $this->artisan('filament-loginguard:ip-intel:test')
        ->expectsOutputToContain('country: US')
        ->expectsOutputToContain('country_name: United States')
        ->expectsOutputToContain('asn: 7922')
        ->expectsOutputToContain('asn_organization: Comcast')
        ->assertExitCode(0);
});

it('accepts an IP argument and restores the enabled flag', function () {
    config()->set('filament-loginguard.ip_intel.enabled', false);

    app()->instance(IpIntelligence::class, new class implements IpIntelligence
    {
        public function lookup(string $ip): ?IpLocation
        {
            return new IpLocation(
                country: $ip === '1.2.3.4' ? 'GB' : null,
                countryName: null,
                city: null,
                subdivision: null,
                latitude: null,
                longitude: null,
                accuracyRadiusKm: null,
                asn: null,
                asnOrganization: null,
            );
        }
    });

    $this->artisan('filament-loginguard:ip-intel:test', ['ip' => '1.2.3.4'])
        ->expectsOutputToContain('Lookup for 1.2.3.4:')
        ->expectsOutputToContain('country: GB')
        ->assertExitCode(0);

    // The command force-enables for the lookup but must leave the flag as-is.
    expect(config('filament-loginguard.ip_intel.enabled'))->toBeFalse();
});
