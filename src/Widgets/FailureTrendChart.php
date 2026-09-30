<?php

namespace SolutionForest\FilamentLoginGuard\Widgets;

use Filament\Widgets\ChartWidget;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;

class FailureTrendChart extends ChartWidget
{
    protected ?string $heading = null;

    protected ?string $maxHeight = '260px';

    protected int | string | array $columnSpan = 'full';

    public ?string $filter = '30';

    public function getHeading(): string
    {
        return (string) __('filament-loginguard::loginguard.charts.failure_trend.heading');
    }

    protected function getType(): string
    {
        return 'line';
    }

    /**
     * @return array<scalar, scalar> | null
     */
    protected function getFilters(): ?array
    {
        $seven = (string) __('filament-loginguard::loginguard.charts.filters.last_7_days');
        $thirty = (string) __('filament-loginguard::loginguard.charts.filters.last_30_days');

        return [
            '7' => $seven,
            '30' => $thirty,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    protected function getData(): array
    {
        $days = (int) ($this->filter ?? '30');
        $days = in_array($days, [7, 30], true) ? $days : 30;

        $start = now()->subDays($days - 1)->startOfDay();

        // Daily failure counts from the fixed window: only rows whose current
        // window started within the range count, weighted by their attempts.
        $daily = LoginAttempt::query()
            ->where('window_started_at', '>=', $start)
            ->where('attempts', '>', 0)
            ->get(['window_started_at', 'attempts'])
            ->groupBy(fn (LoginAttempt $row): string => $row->window_started_at->format('Y-m-d'))
            ->map(fn ($rows): int => (int) $rows->sum('attempts'));

        $labels = [];
        $values = [];

        for ($day = $start->copy(); $day->lte(now()); $day->addDay()) {
            $key = $day->format('Y-m-d');
            $labels[] = $day->format('m-d');
            $values[] = $daily->get($key, 0);
        }

        return [
            'datasets' => [
                [
                    'label' => (string) __('filament-loginguard::loginguard.charts.failure_trend.dataset'),
                    'data' => $values,
                    'fill' => 'start',
                    'backgroundColor' => 'rgba(239, 68, 68, 0.15)',
                    'borderColor' => '#ef4444',
                    'tension' => 0.3,
                    'pointRadius' => 2,
                ],
            ],
            'labels' => $labels,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    protected function getOptions(): array
    {
        return [
            'plugins' => [
                'legend' => [
                    'display' => false,
                ],
            ],
            'scales' => [
                'y' => [
                    'beginAtZero' => true,
                    'ticks' => [
                        'precision' => 0,
                    ],
                ],
            ],
        ];
    }
}
