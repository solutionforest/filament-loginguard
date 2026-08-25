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
}
