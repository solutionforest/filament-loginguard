<?php

namespace SolutionForest\FilamentLoginGuard\Support;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\IpUtils;

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

        $binary = @inet_pton($ip);

        if ($binary === false) {
            return $ip;
        }

        if (str_starts_with($binary, str_repeat("\0", 10) . "\xff\xff")) {
            $binary = substr($binary, 12);
        }

        return (string) inet_ntop($binary);
    }

    /**
     * Older releases stored some mapped IPv4 inputs in inet_ntop's mapped
     * notation. New rows use the first key; reads include the historical key.
     *
     * @return non-empty-list<string>
     */
    public static function storedKeys(string $ip): array
    {
        $canonical = self::normalize($ip);

        return filter_var($canonical, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
            ? [$canonical, '::ffff:' . $canonical]
            : [$ip];
    }

    /**
     * Resolve the real client IP of the current request.
     *
     * When the immediate request IP matches a proxy in
     * `filament-loginguard.lockout.trusted_proxies` (exact IP or CIDR), the
     * X-Forwarded-For chain is walked right-to-left, skipping every trusted
     * proxy, and the first untrusted address is returned. This prevents
     * clients from spoofing their IP by appending entries to the header.
     * Without trusted proxies (or with an unusable chain), the request IP
     * itself is used. The result is always passed through normalize().
     */
    public static function fromRequest(?Request $request = null): string
    {
        $request ??= request();

        $ip = (string) $request->ip();
        $trusted = array_values(array_filter(
            (array) config('filament-loginguard.lockout.trusted_proxies', []),
            fn (mixed $entry): bool => is_string($entry) && $entry !== '',
        ));

        if ($trusted === [] || $ip === '' || ! self::isTrusted($ip, $trusted)) {
            return self::normalize($ip);
        }

        $header = $request->header('X-Forwarded-For', '');

        $forwarded = is_string($header) ? array_map('trim', explode(',', $header)) : [];

        // Walk the chain right-to-left: entries right of the client were added by
        // proxies we control, so they can be trusted; the first untrusted entry
        // (or the leftmost entry when the whole chain is trusted) is the client.
        for ($i = count($forwarded) - 1; $i >= 0; $i--) {
            $candidate = $forwarded[$i];

            if ($candidate === '') {
                continue;
            }

            if (self::isTrusted($candidate, $trusted)) {
                continue;
            }

            return self::normalize($candidate);
        }

        return self::normalize($ip);
    }

    /**
     * @param  array<int, string>  $trusted
     */
    private static function isTrusted(string $ip, array $trusted): bool
    {
        try {
            return IpUtils::checkIp($ip, $trusted);
        } catch (\InvalidArgumentException) {
            return false;
        }
    }
}
