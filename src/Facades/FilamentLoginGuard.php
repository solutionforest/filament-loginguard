<?php

namespace SolutionForest\FilamentLoginGuard\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \SolutionForest\FilamentLoginGuard\FilamentLoginGuard
 */
class FilamentLoginGuard extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \SolutionForest\FilamentLoginGuard\FilamentLoginGuard::class;
    }
}
