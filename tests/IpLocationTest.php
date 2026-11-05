<?php

use SolutionForest\FilamentLoginGuard\IpLocation;

it('exposes nullable fields and serializes to a metadata-friendly array', function () {
    $location = new IpLocation(
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

    expect($location->country)->toBe('US')
        ->and($location->countryName)->toBe('United States')
        ->and($location->city)->toBe('Minneapolis')
        ->and($location->asn)->toBe(7922)
        ->and($location->toArray())->toBe([
            'country' => 'US',
            'country_name' => 'United States',
            'city' => 'Minneapolis',
            'subdivision' => 'Minnesota',
            'latitude' => 44.9733,
            'longitude' => -93.2323,
            'accuracy_radius_km' => 20,
            'asn' => 7922,
            'asn_organization' => 'Comcast',
        ]);
});

it('allows every field to be null', function () {
    $location = new IpLocation(
        country: null,
        countryName: null,
        city: null,
        subdivision: null,
        latitude: null,
        longitude: null,
        accuracyRadiusKm: null,
        asn: null,
        asnOrganization: null,
    );

    expect($location->toArray())->toBe([
        'country' => null,
        'country_name' => null,
        'city' => null,
        'subdivision' => null,
        'latitude' => null,
        'longitude' => null,
        'accuracy_radius_km' => null,
        'asn' => null,
        'asn_organization' => null,
    ]);
});
