<?php

namespace SolutionForest\FilamentLoginGuard\Widgets;

use Filament\Widgets\StatsOverviewWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;
use SolutionForest\FilamentLoginGuard\Models\LockoutHistory;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;

class LoginGuardStats extends StatsOverviewWidget
{
    /**
     * @return array<int, Stat>
     */
    protected function getStats(): array
    {
        $dayAgo = now()->subDay();

        return [
            // Sum over active windows only: `window_started_at` marks when the
            // currently-counting window began, so attempts from outside the
            // window are never included.
            Stat::make(
                (string) __('filament-loginguard::loginguard.stats.failed_attempts_24h'),
                LoginAttempt::query()
                    ->where('window_started_at', '>=', $dayAgo)
                    ->sum('attempts'),
            )
                ->description((string) __('filament-loginguard::loginguard.stats.last_24h'))
                ->descriptionIcon('heroicon-o-exclamation-triangle')
                ->color('danger'),

            // Count distinct locked (ip, email) pairs via the append-only
            // history: an aggregate IP lock touches many rows that all share
            // the same triggered-by pair, which would otherwise overcount.
            Stat::make(
                (string) __('filament-loginguard::loginguard.stats.locked_out_now'),
                LockoutHistory::query()
                    ->where('locked_until', '>', now())
                    ->selectRaw('count(distinct ip || "|" || email) as aggregate')
                    ->value('aggregate'),
            )
                ->description((string) __('filament-loginguard::loginguard.stats.active_lockouts'))
                ->descriptionIcon('heroicon-o-lock-closed')
                ->color('danger'),

            // Count actual successful logins (success_count deltas), not rows.
            Stat::make(
                (string) __('filament-loginguard::loginguard.stats.successful_logins_24h'),
                LoginAttempt::query()
                    ->where('last_success_at', '>=', $dayAgo)
                    ->sum('success_count'),
            )
                ->description((string) __('filament-loginguard::loginguard.stats.last_24h'))
                ->descriptionIcon('heroicon-o-check-circle')
                ->color('success'),
        ];
    }
}
