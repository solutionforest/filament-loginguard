<?php

namespace SolutionForest\FilamentLoginGuard\Widgets;

use Filament\Widgets\StatsOverviewWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;
use SolutionForest\FilamentLoginGuard\Models\LoginGuardLock;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;

class LoginGuardStats extends StatsOverviewWidget
{
    /**
     * @return array<int, Stat>
     */
    protected function getStats(): array
    {
        $dayAgo = now()->subDay();

        return [
            // Actual failed-login events in the last 24h, from the append-only
            // event log.
            Stat::make(
                (string) __('filament-loginguard::loginguard.stats.failed_attempts_24h'),
                SecurityEvent::query()
                    ->where('type', SecurityEvent::TYPE_LOGIN_FAILED)
                    ->where('occurred_at', '>=', $dayAgo)
                    ->count(),
            )
                ->description((string) __('filament-loginguard::loginguard.stats.last_24h'))
                ->descriptionIcon('heroicon-o-exclamation-triangle')
                ->color('danger'),

            // Active locks straight from the lock-state table: early-released
            // locks (admin unblock / self-unlock) disappear the moment they are
            // lifted, and IP and email locks are counted individually.
            Stat::make(
                (string) __('filament-loginguard::loginguard.stats.locked_out_now'),
                LoginGuardLock::activeQuery()->count(),
            )
                ->description((string) __('filament-loginguard::loginguard.stats.active_lockouts'))
                ->descriptionIcon('heroicon-o-lock-closed')
                ->color('danger'),

            // Actual successful-login events in the last 24h, from the
            // append-only event log.
            Stat::make(
                (string) __('filament-loginguard::loginguard.stats.successful_logins_24h'),
                SecurityEvent::query()
                    ->where('type', SecurityEvent::TYPE_LOGIN_SUCCEEDED)
                    ->where('occurred_at', '>=', $dayAgo)
                    ->count(),
            )
                ->description((string) __('filament-loginguard::loginguard.stats.last_24h'))
                ->descriptionIcon('heroicon-o-check-circle')
                ->color('success'),
        ];
    }
}
