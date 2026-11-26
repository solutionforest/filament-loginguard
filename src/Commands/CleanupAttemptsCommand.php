<?php

namespace SolutionForest\FilamentLoginGuard\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use SolutionForest\FilamentLoginGuard\LoginGuardService;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;

class CleanupAttemptsCommand extends Command
{
    public $signature = 'filament-loginguard:cleanup-attempts {--all : Delete every recorded attempt row}';

    public $description = 'Delete expired and stale login attempt records';

    public function handle(): int
    {
        $query = LoginAttempt::query();

        if ($this->option('all')) {
            $deleted = filament_loginguard_intval($query->delete());
            $this->info("Deleted {$deleted} rows.");

            return self::SUCCESS;
        }

        $windowMinutes = filament_loginguard_config_int('filament-loginguard.lockout.attempts_window_minutes', 30);

        $deleted = $query
            ->where('last_attempt_at', '<', now()->subMinutes($windowMinutes))
            // The current lock state lives in the locks table (scoped per IP /
            // email / pair). A row is only stale when none of its scopes has an
            // active lock — the legacy per-row `locked_until` column is kept as
            // an extra guard for rows created before the lock model existed.
            ->where(function (Builder $query): void {
                $query->whereNull('locked_until')->orWhere('locked_until', '<', now());
            })
            ->whereNotExists(app(LoginGuardService::class)->activeLocksForAttempt())
            ->delete();

        $this->info("Deleted {$deleted} stale rows.");

        return self::SUCCESS;
    }
}
