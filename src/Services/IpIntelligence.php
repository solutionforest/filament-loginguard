<?php

namespace SolutionForest\FilamentLoginGuard\Services;

use SolutionForest\FilamentLoginGuard\IpLocation;

interface IpIntelligence
{
    /**
     * Resolve structured location / network signals for an IP address.
     *
     * Returns null when the feature is disabled, the provider is unavailable,
     * or the address cannot be resolved. Implementations must never throw —
     * IP intelligence must not break the login flow.
     */
    public function lookup(string $ip): ?IpLocation;
}
