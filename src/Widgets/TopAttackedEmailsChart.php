<?php

namespace SolutionForest\FilamentLoginGuard\Widgets;

use Filament\Widgets\ChartWidget;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;

class TopAttackedEmailsChart extends ChartWidget
{
    protected ?string $maxHeight = '300px';

    protected int | string | array $columnSpan = 1;

    public function getHeading(): string
    {
        return (string) __('filament-loginguard::loginguard.charts.top_emails.heading');
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
        // True 24h failures per email from the event log, aggregated across all
        // source IPs — a victim hit from three IPs shows as one combined total.
        $top = SecurityEvent::query()
            ->where('type', SecurityEvent::TYPE_LOGIN_FAILED)
            ->where('occurred_at', '>=', now()->subDay())
            ->whereNotNull('email')
            ->selectRaw('email, count(*) as aggregate')
            ->groupBy('email')
            ->orderByDesc('aggregate')
            ->limit(10)
            ->get();

        return [
            'datasets' => [
                [
                    'label' => (string) __('filament-loginguard::loginguard.charts.top_emails.dataset'),
                    'data' => $top->pluck('aggregate')->all(),
                    'backgroundColor' => '#f97316',
                    'borderRadius' => 4,
                    'maxBarThickness' => 28,
                ],
            ],
            'labels' => $top->pluck('email')->all(),
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
