<?php

namespace SolutionForest\FilamentLoginGuard;

final class LockoutResult
{
    public function __construct(
        public readonly bool $locked,
        public readonly int $secondsRemaining = 0,
        public readonly int $minutes = 0,
    ) {}
}
