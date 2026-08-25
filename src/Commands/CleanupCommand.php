<?php

namespace SolutionForest\FilamentLoginGuard\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;

class CleanupCommand extends Command
{
    public $signature = 'filament-loginguard:cleanup {--all : Delete every recorded attempt row}';

    public $description = 'Delete expired and stale login attempt records';

    public function handle(): int
    {
        $query = LoginAttempt::query();

        if ($this->option('all')) {
            $deleted = $query->delete();
            $this->info("Deleted {$deleted} rows.");

            return self::SUCCESS;
        }

        $windowMinutes = (int) config('filament-loginguard.lockout.attempts_window_minutes', 30);

        $deleted = $query
            ->where('last_attempt_at', '<', now()->subMinutes($windowMinutes))
            ->where(function (Builder $query): void {
                $query->whereNull('locked_until')->orWhere('locked_until', '<', now());
            })
            ->delete();

        $this->info("Deleted {$deleted} stale rows.");

        return self::SUCCESS;
    }
}
