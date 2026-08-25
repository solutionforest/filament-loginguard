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
        if ($this->user_agent === null || $this->user_agent === '') {
            return null;
        }

        $parser = new Parser($this->user_agent);

        $parts = array_values(array_filter([
            $parser->browser->getName(),
            $parser->os->getName(),
        ]));

        return $parts === [] ? null : implode(' on ', $parts);
    }
}
