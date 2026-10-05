<?php

namespace SolutionForest\FilamentLoginGuard\Widgets;

use Filament\Widgets\ChartWidget;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;

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
        // True 24h failures per source IP from the event log, aggregated across
        // all attacked emails.
        $top = SecurityEvent::query()
            ->where('type', SecurityEvent::TYPE_LOGIN_FAILED)
            ->where('occurred_at', '>=', now()->subDay())
            ->whereNotNull('ip')
            ->selectRaw('ip, count(*) as aggregate')
            ->groupBy('ip')
            ->orderByDesc('aggregate')
            ->limit(10)
            ->get();

        return [
            'datasets' => [
                [
                    'label' => (string) __('filament-loginguard::loginguard.charts.top_ips.dataset'),
                    'data' => $top->pluck('aggregate')->all(),
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
