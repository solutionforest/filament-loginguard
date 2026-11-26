<?php

use Carbon\Carbon;
use Filament\Facades\Filament;
use Filament\Panel;
use Filament\Widgets\WidgetConfiguration;
use Livewire\Livewire;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;
use SolutionForest\FilamentLoginGuard\Pages\LoginGuard;
use SolutionForest\FilamentLoginGuard\Tests\Support\TestUser;
use SolutionForest\FilamentLoginGuard\Widgets\FailureTrendChart;
use SolutionForest\FilamentLoginGuard\Widgets\TopAttackedEmailsChart;
use SolutionForest\FilamentLoginGuard\Widgets\TopSourceIpsChart;

beforeEach(function () {
    Carbon::setTestNow('2026-01-01 00:00:00');

    $panel = Panel::make()
        ->id('admin')
        ->default()
        ->plugin(FilamentLoginGuardPlugin::make());

    Filament::registerPanel($panel);
    Filament::setCurrentPanel($panel);

    $this->actingAs(new TestUser);
});

afterEach(function () {
    Carbon::setTestNow(null);
});

/** Pull the computed chart data off the widget instance (protected → readable in tests). */
function chartData(FailureTrendChart | TopAttackedEmailsChart | TopSourceIpsChart $widget): array
{
    $method = new ReflectionMethod($widget, 'getCachedData');

    return $method->invoke($widget);
}

function recordChartEvent(?string $ip, ?string $email, Carbon $at, string $type = SecurityEvent::TYPE_LOGIN_FAILED): void
{
    SecurityEvent::query()->create([
        'type' => $type,
        'ip' => $ip,
        'email' => $email,
        'occurred_at' => $at,
    ]);
}

it('charts the daily failure trend inside the selected window', function () {
    // Two failures two days ago; one 40 days ago (outside the 30-day range).
    recordChartEvent('1.2.3.4', 'a@example.com', now()->subDays(2)->addHours(3));
    recordChartEvent('1.2.3.4', 'a@example.com', now()->subDays(2)->addHours(4));
    recordChartEvent('1.2.3.4', 'b@example.com', now()->subDays(40));

    $chart = Livewire::test(FailureTrendChart::class, ['filter' => '30']);
    $data = chartData($chart->instance());

    $values = $data['datasets'][0]['data'];

    // 30 labels (one per day), the stale event is not counted, the two fresh
    // events appear two days ago.
    expect(count($data['labels']))->toBe(30)
        ->and(array_sum($values))->toBe(2)
        ->and($values[count($values) - 3])->toBe(2);
});

it('updates the trend to seven calendar days and counts only failures', function () {
    recordChartEvent(null, null, now()->subDays(6));
    recordChartEvent('1.2.3.4', 'a@example.com', now()->subDays(6)->subSecond());
    recordChartEvent('1.2.3.4', 'a@example.com', now(), SecurityEvent::TYPE_LOGIN_SUCCEEDED);
    recordChartEvent('1.2.3.4', 'a@example.com', now());

    $chart = Livewire::test(FailureTrendChart::class)->set('filter', '7');
    $data = chartData($chart->instance());

    expect($data['labels'])->toBe(['12-26', '12-27', '12-28', '12-29', '12-30', '12-31', '01-01'])
        ->and($data['datasets'][0]['data'])->toBe([1, 0, 0, 0, 0, 0, 1]);
});

it('falls back to 30 days when the trend filter is missing or unsupported', function (?string $filter) {
    recordChartEvent('1.2.3.4', 'a@example.com', now()->subDays(10));

    $chart = Livewire::test(FailureTrendChart::class, ['filter' => $filter]);
    $data = chartData($chart->instance());

    // Falls back to 30 days, so the 10-day-old failure is included.
    expect(count($data['labels']))->toBe(30)
        ->and(array_sum($data['datasets'][0]['data']))->toBe(1);
})->with(['missing' => [null], 'unsupported' => ['999']]);

it('aggregates the top attacked emails across source ips', function () {
    // The same victim attacked from three different IPs: one combined total.
    recordChartEvent('1.1.1.1', 'victim@example.com', now()->subHour());
    recordChartEvent('2.2.2.2', 'victim@example.com', now()->subHour());
    recordChartEvent('3.3.3.3', 'victim@example.com', now()->subHours(2));
    // A fresh event 3 days back must not count in the 24h leaderboard.
    recordChartEvent('1.1.1.1', 'stale@example.com', now()->subDays(3));

    $chart = Livewire::test(TopAttackedEmailsChart::class);
    $data = chartData($chart->instance());

    expect($data['labels'])->toBe(['victim@example.com'])
        ->and($data['datasets'][0]['data'])->toBe([3]);
});

it('aggregates the top source ips across attacked emails', function () {
    recordChartEvent('1.1.1.1', 'a@example.com', now()->subHour());
    recordChartEvent('1.1.1.1', 'b@example.com', now()->subHour());
    recordChartEvent('2.2.2.2', 'a@example.com', now()->subHour());

    $chart = Livewire::test(TopSourceIpsChart::class);
    $data = chartData($chart->instance());

    expect($data['labels'])->toBe(['1.1.1.1', '2.2.2.2'])
        ->and($data['datasets'][0]['data'])->toBe([2, 1]);
});

it('ranks ten named groups using only failures inside the last 24 hours', function (string $widget, string $labelTemplate) {
    for ($count = 1; $count <= 11; $count++) {
        for ($event = 0; $event < $count; $event++) {
            recordChartEvent("10.0.0.{$count}", "target-{$count}@example.com", now()->subDay());
        }
    }

    for ($event = 0; $event < 12; $event++) {
        recordChartEvent(null, null, now());
    }

    recordChartEvent('10.0.0.11', 'target-11@example.com', now()->subDay()->subSecond());
    recordChartEvent('10.0.0.11', 'target-11@example.com', now(), SecurityEvent::TYPE_LOGIN_SUCCEEDED);
    recordChartEvent('10.0.0.11', 'target-11@example.com', now(), SecurityEvent::TYPE_LOCKOUT_STARTED);

    $data = chartData(Livewire::test($widget)->instance());

    expect($data['labels'])->toBe(array_map(fn (int $count) => sprintf($labelTemplate, $count), range(11, 2)))
        ->and($data['datasets'][0]['data'])->toBe([11, 10, 9, 8, 7, 6, 5, 4, 3, 2]);
})->with([
    'attacked emails' => [TopAttackedEmailsChart::class, 'target-%d@example.com'],
    'source IPs' => [TopSourceIpsChart::class, '10.0.0.%d'],
]);

it('registers the charts on the admin page by default', function () {
    LoginAttempt::query()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'attempts' => 4,
        'window_started_at' => now()->subHour(),
    ]);

    // The charts are lazy Livewire widgets; their content is not part of the
    // page HTML, so assert the widget registration instead.
    $widgets = collect(Livewire::test(LoginGuard::class)->instance()->getVisibleHeaderWidgets())
        ->map(fn ($widget) => $widget instanceof WidgetConfiguration ? $widget->widget : $widget)
        ->all();
    expect($widgets)->toContain(FailureTrendChart::class)
        ->toContain(TopAttackedEmailsChart::class)
        ->toContain(TopSourceIpsChart::class);
});
