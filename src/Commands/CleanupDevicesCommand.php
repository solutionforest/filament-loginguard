<?php

namespace SolutionForest\FilamentLoginGuard\Commands;

use Illuminate\Console\Command;
use SolutionForest\FilamentLoginGuard\Services\DeviceManager;

class CleanupDevicesCommand extends Command
{
    public $signature = 'filament-loginguard:cleanup-devices';

    public $description = 'Remove device↔session mappings for dead sessions and devices beyond the retention window';

    public function handle(DeviceManager $manager): int
    {
        $manager->cleanup();

        $this->info('Device cleanup finished.');

        return self::SUCCESS;
    }
}
