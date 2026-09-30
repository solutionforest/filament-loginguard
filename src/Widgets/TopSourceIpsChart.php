<?php

namespace SolutionForest\FilamentLoginGuard\Widgets;

use Filament\Widgets\ChartWidget;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;

class TopSourceIpsChart extends ChartWidget
{
    protected ?string $maxHeight = '300px';

    protected int | string | array $columnSpan = 1;

    public function getHeading(): string
    {
        return (string) __('filament-loginguard::loginguard.charts.top_ips.heading');
    }

    protected function getType(): string
    {
        return 'bar';
    }

    /**
     * @return array<string, mixed>
     */
    protected function getData(): array
    {
        // Windowed failures per source IP: only attempts inside an active
        // window count, matching the lockout semantics.
        $top = LoginAttempt::query()
            ->where('window_started_at', '>=', now()->subDay()->startOfDay())
            ->where('attempts', '>', 0)
            ->orderByDesc('attempts')
            ->limit(10)
            ->get(['ip', 'attempts']);

        return [
            'datasets' => [
                [
                    'label' => (string) __('filament-loginguard::loginguard.charts.top_ips.dataset'),
                    'data' => $top->pluck('attempts')->all(),
                    'backgroundColor' => '#3b82f6',
                    'borderRadius' => 4,
                    'maxBarThickness' => 28,
                ],
            ],
            'labels' => $top->pluck('ip')->all(),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    protected function getOptions(): array
    {
        return [
            'indexAxis' => 'y',
            'plugins' => [
                'legend' => [
                    'display' => false,
                ],
            ],
            'scales' => [
                'x' => [
                    'beginAtZero' => true,
                    'ticks' => [
                        'precision' => 0,
                    ],
                ],
            ],
        ];
    }
}
