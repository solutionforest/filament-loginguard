<?php

namespace SolutionForest\FilamentLoginGuard\Widgets;

use Filament\Widgets\StatsOverviewWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;
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
            Stat::make(
                (string) __('filament-loginguard::loginguard.stats.failed_attempts_24h'),
                LoginAttempt::query()
                    ->where('last_attempt_at', '>=', $dayAgo)
                    ->sum('attempts'),
            )
                ->description((string) __('filament-loginguard::loginguard.stats.last_24h'))
                ->descriptionIcon('heroicon-o-exclamation-triangle')
                ->color('danger'),

            Stat::make(
                (string) __('filament-loginguard::loginguard.stats.locked_out_now'),
                LoginAttempt::query()->where('locked_until', '>', now())->count(),
            )
                ->description((string) __('filament-loginguard::loginguard.stats.active_lockouts'))
                ->descriptionIcon('heroicon-o-lock-closed')
                ->color('danger'),

            Stat::make(
                (string) __('filament-loginguard::loginguard.stats.successful_logins_24h'),
                LoginAttempt::query()
                    ->where('last_success_at', '>=', $dayAgo)
                    ->count(),
            )
                ->description((string) __('filament-loginguard::loginguard.stats.last_24h'))
                ->descriptionIcon('heroicon-o-check-circle')
                ->color('success'),
        ];
    }
}
