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

        return trim("{$parser->browser->getName()} on {$parser->os->getName()}");
    }
}
