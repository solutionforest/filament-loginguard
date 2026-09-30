<?php

namespace SolutionForest\FilamentLoginGuard\Widgets;

use Filament\Widgets\ChartWidget;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;

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
        // Windowed failures per email: only attempts inside an active window
        // count, matching the lockout semantics.
        $top = LoginAttempt::query()
            ->where('window_started_at', '>=', now()->subDay()->startOfDay())
            ->where('attempts', '>', 0)
            ->orderByDesc('attempts')
            ->limit(10)
            ->get(['email', 'attempts']);

        return [
            'datasets' => [
                [
                    'label' => (string) __('filament-loginguard::loginguard.charts.top_emails.dataset'),
                    'data' => $top->pluck('attempts')->all(),
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
