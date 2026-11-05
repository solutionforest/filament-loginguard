<?php

namespace SolutionForest\FilamentLoginGuard;

/**
 * Structured location / network signals resolved from an IP address.
 *
 * Every field is nullable: the feature may be disabled, the address may be
 * unmapped, or only a subset of the databases may be configured.
 */
final class IpLocation
{
    public function __construct(
        public readonly ?string $country,
        public readonly ?string $countryName,
        public readonly ?string $city,
        public readonly ?string $subdivision,
        public readonly ?float $latitude,
        public readonly ?float $longitude,
        public readonly ?int $accuracyRadiusKm,
        public readonly ?int $asn,
        public readonly ?string $asnOrganization,
    ) {}

    /**
     * @return array<string, string|int|float|null>
     */
    public function toArray(): array
    {
        return [
            'country' => $this->country,
            'country_name' => $this->countryName,
            'city' => $this->city,
            'subdivision' => $this->subdivision,
            'latitude' => $this->latitude,
            'longitude' => $this->longitude,
            'accuracy_radius_km' => $this->accuracyRadiusKm,
            'asn' => $this->asn,
            'asn_organization' => $this->asnOrganization,
        ];
    }
}
