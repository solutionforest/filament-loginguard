<?php

namespace SolutionForest\FilamentLoginGuard\Services;

use GeoIp2\Database\Reader;
use SolutionForest\FilamentLoginGuard\IpLocation;
use SolutionForest\FilamentLoginGuard\Support\IpAddress;

/**
 * MaxMind GeoLite2 / GeoIP2 backed IpIntelligence.
 *
 * Reads local .mmdb files (GeoLite2-Country / -City / -ASN). The optional
 * `geoip2/geoip2` package is a suggested dependency: when it is absent, or
 * when the feature / databases are not configured, lookup() degrades to null
 * and never affects the login flow.
 */
class MaxmindIpIntelligence implements IpIntelligence
{
    /** @var array<string, Reader|null> cached readers keyed by database kind */
    private array $readers = [];

    public function lookup(string $ip): ?IpLocation
    {
        if (! $this->enabled()) {
            return null;
        }

        $ip = IpAddress::normalize($ip);

        if ($ip === '') {
            return null;
        }

        $data = [
            'country' => null,
            'country_name' => null,
            'city' => null,
            'subdivision' => null,
            'latitude' => null,
            'longitude' => null,
            'accuracy_radius_km' => null,
            'asn' => null,
            'asn_organization' => null,
        ];

        $found = $this->hydrateCity($ip, $data);
        $found = $this->hydrateCountry($ip, $data) || $found;
        $found = $this->hydrateAsn($ip, $data) || $found;

        if (! $found) {
            return null;
        }

        return new IpLocation(
            country: $data['country'],
            countryName: $data['country_name'],
            city: $data['city'],
            subdivision: $data['subdivision'],
            latitude: $data['latitude'],
            longitude: $data['longitude'],
            accuracyRadiusKm: $data['accuracy_radius_km'],
            asn: $data['asn'],
            asnOrganization: $data['asn_organization'],
        );
    }

    /**
     * Fill country + city + coordinates from the GeoLite2-City database.
     *
     * @param  array<string, string|int|float|null>  $data
     */
    private function hydrateCity(string $ip, array &$data): bool
    {
        $reader = $this->reader('city');

        if ($reader === null) {
            return false;
        }

        try {
            $record = $reader->city($ip);
        } catch (\Throwable) {
            return false;
        }

        $data['country'] ??= $record->country->isoCode;
        $data['country_name'] ??= $record->country->name;
        $data['city'] = $record->city->name;
        $data['subdivision'] = $record->mostSpecificSubdivision->name;
        $data['latitude'] = $record->location->latitude;
        $data['longitude'] = $record->location->longitude;
        $data['accuracy_radius_km'] = $record->location->accuracyRadius;

        return $data['country'] !== null
            || $data['city'] !== null
            || $data['latitude'] !== null;
    }

    /**
     * Fill country from the GeoLite2-Country database (used when City is absent).
     *
     * @param  array<string, string|int|float|null>  $data
     */
    private function hydrateCountry(string $ip, array &$data): bool
    {
        $reader = $this->reader('country');

        if ($reader === null) {
            return false;
        }

        try {
            $record = $reader->country($ip);
        } catch (\Throwable) {
            return false;
        }

        $data['country'] ??= $record->country->isoCode;
        $data['country_name'] ??= $record->country->name;

        return $data['country'] !== null;
    }

    /**
     * Fill ASN from the GeoLite2-ASN database.
     *
     * @param  array<string, string|int|float|null>  $data
     */
    private function hydrateAsn(string $ip, array &$data): bool
    {
        $reader = $this->reader('asn');

        if ($reader === null) {
            return false;
        }

        try {
            $record = $reader->asn($ip);
        } catch (\Throwable) {
            return false;
        }

        $data['asn'] = $record->autonomousSystemNumber;
        $data['asn_organization'] = $record->autonomousSystemOrganization;

        return $data['asn'] !== null;
    }

    /**
     * Lazily open (and cache) the reader for a database kind. Returns null when
     * the geoip2 package is missing, the path is unconfigured or missing, or
     * the file cannot be read.
     */
    private function reader(string $kind): ?Reader
    {
        if (array_key_exists($kind, $this->readers)) {
            return $this->readers[$kind];
        }

        if (! class_exists(Reader::class)) {
            return $this->readers[$kind] = null;
        }

        $path = config("filament-loginguard.ip_intel.databases.{$kind}");

        if (! is_string($path) || $path === '' || ! is_file($path)) {
            return $this->readers[$kind] = null;
        }

        try {
            return $this->readers[$kind] = new Reader($path);
        } catch (\Throwable) {
            return $this->readers[$kind] = null;
        }
    }

    private function enabled(): bool
    {
        return (bool) config('filament-loginguard.ip_intel.enabled', false);
    }
}
