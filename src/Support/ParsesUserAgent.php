<?php

namespace SolutionForest\FilamentLoginGuard\Support;

use WhichBrowser\Parser;

trait ParsesUserAgent
{
    /**
     * Human-readable device description, e.g. "Chrome on macOS".
     */
    public function getDeviceNameAttribute(): ?string
    {
        return static::parseDeviceName($this->user_agent);
    }

    /**
     * Parse a user agent into a "browser on os" fingerprint, e.g. "Chrome on macOS".
     * Returns null when nothing meaningful can be extracted.
     */
    public static function parseDeviceName(?string $userAgent): ?string
    {
        if ($userAgent === null || $userAgent === '') {
            return null;
        }

        $parser = new Parser($userAgent);

        $parts = array_values(array_filter([
            $parser->browser->getName(),
            $parser->os->getName(),
        ]));

        return $parts === [] ? null : implode(' on ', $parts);
    }

    /**
     * Coarse device category for icon selection: desktop, mobile, tablet or
     * unknown. Deliberately conservative — scripts, bots and unrecognized
     * clients fall through to "unknown" so the UI never guesses a phone or
     * laptop from a request that carries no hardware hint.
     */
    public static function parseDeviceType(?string $userAgent): string
    {
        if ($userAgent === null || $userAgent === '') {
            return 'unknown';
        }

        $type = (new Parser($userAgent))->getType();

        return match (true) {
            str_starts_with($type, 'desktop') => 'desktop',
            str_starts_with($type, 'tablet'), str_starts_with($type, 'ereader') => 'tablet',
            str_starts_with($type, 'mobile') => 'mobile',
            default => 'unknown',
        };
    }

    /**
     * The browser name alone, or null when it can't be determined.
     */
    public static function parseBrowserName(?string $userAgent): ?string
    {
        if ($userAgent === null || $userAgent === '') {
            return null;
        }

        $name = (new Parser($userAgent))->browser->getName();

        return $name !== '' ? $name : null;
    }

    /**
     * The operating-system name alone, or null when it can't be determined.
     */
    public static function parseOsName(?string $userAgent): ?string
    {
        if ($userAgent === null || $userAgent === '') {
            return null;
        }

        $name = (new Parser($userAgent))->os->getName();

        return $name !== '' ? $name : null;
    }
}
