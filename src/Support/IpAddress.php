<?php

namespace SolutionForest\FilamentLoginGuard\Support;

final class IpAddress
{
    /**
     * Canonicalize an IP address so the same client always maps to the same key,
     * regardless of protocol or textual representation:
     * - IPv4-mapped IPv6 ("::ffff:1.2.3.4") is reduced to plain IPv4 ("1.2.3.4"),
     * - otherwise inet_pton + inet_ntop lowercases, drops leading zeros and compresses IPv6.
     *
     * Unrecognized strings are returned unchanged.
     */
    public static function normalize(?string $ip): string
    {
        $ip = trim((string) $ip);

        if ($ip === '') {
            return '';
        }

        if (str_starts_with($ip, '::ffff:') && filter_var(substr($ip, 7), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip = substr($ip, 7);
        }

        $binary = @inet_pton($ip);

        return $binary === false ? $ip : (string) inet_ntop($binary);
    }
}
