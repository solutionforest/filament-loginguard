<?php

namespace SolutionForest\FilamentLoginGuard\Events;

use Illuminate\Foundation\Events\Dispatchable;

class LoginLockedOut
{
    use Dispatchable;

    public function __construct(
        public readonly string $ip,
        public readonly string $email,
        public readonly int $lockedForMinutes,
    ) {}
}
