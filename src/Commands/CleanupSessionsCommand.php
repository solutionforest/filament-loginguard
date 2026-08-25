<?php

namespace SolutionForest\FilamentLoginGuard\Commands;

use Illuminate\Console\Command;
use SolutionForest\FilamentLoginGuard\Models\UserSession;

class CleanupSessionsCommand extends Command
{
    public $signature = 'filament-loginguard:cleanup-sessions {--all : Delete every session row}';

    public $description = 'Delete expired session records';

    public function handle(): int
    {
        $query = UserSession::query();

        if ($this->option('all')) {
            $deleted = $query->delete();
            $this->info("Deleted {$deleted} rows.");

            return self::SUCCESS;
        }

        $lifetimeMinutes = (int) config('session.lifetime', 120);

        $deleted = $query
            ->where('last_activity', '<', now()->subMinutes($lifetimeMinutes)->timestamp)
            ->delete();

        $this->info("Deleted {$deleted} expired rows.");

        return self::SUCCESS;
    }
}
