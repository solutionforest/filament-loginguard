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

function recordFailureEvent(string $ip, string $email, Carbon $at): void
{
    SecurityEvent::query()->create([
        'type' => SecurityEvent::TYPE_LOGIN_FAILED,
        'ip' => $ip,
        'email' => $email,
        'occurred_at' => $at,
    ]);
}

it('charts the daily failure trend inside the selected window', function () {
    // Two failures two days ago; one 40 days ago (outside the 30-day range).
    recordFailureEvent('1.2.3.4', 'a@example.com', now()->subDays(2)->addHours(3));
    recordFailureEvent('1.2.3.4', 'a@example.com', now()->subDays(2)->addHours(4));
    recordFailureEvent('1.2.3.4', 'b@example.com', now()->subDays(40));

    $chart = Livewire::test(FailureTrendChart::class, ['filter' => '30']);
    $data = chartData($chart->instance());

    $values = $data['datasets'][0]['data'];

    // 30 labels (one per day), the stale event is not counted, the two fresh
    // events appear two days ago.
    expect(count($data['labels']))->toBe(30)
        ->and(array_sum($values))->toBe(2)
        ->and($values[count($values) - 3])->toBe(2);
});

it('limits the trend to 7 days with the filter', function () {
    recordFailureEvent('1.2.3.4', 'a@example.com', now()->subDays(10));

    $chart = Livewire::test(FailureTrendChart::class, ['filter' => '7']);
    $data = chartData($chart->instance());

    expect(count($data['labels']))->toBe(7)
        ->and(array_sum($data['datasets'][0]['data']))->toBe(0);
});

it('ignores invalid filter values', function () {
    recordFailureEvent('1.2.3.4', 'a@example.com', now()->subDays(10));

    $chart = Livewire::test(FailureTrendChart::class, ['filter' => '999']);
    $data = chartData($chart->instance());

    // Falls back to 30 days, so the 10-day-old failure is included.
    expect(count($data['labels']))->toBe(30)
        ->and(array_sum($data['datasets'][0]['data']))->toBe(1);
});

it('aggregates the top attacked emails across source ips', function () {
    // The same victim attacked from three different IPs: one combined total.
    recordFailureEvent('1.1.1.1', 'victim@example.com', now()->subHour());
    recordFailureEvent('2.2.2.2', 'victim@example.com', now()->subHour());
    recordFailureEvent('3.3.3.3', 'victim@example.com', now()->subHours(2));
    // A fresh event 3 days back must not count in the 24h leaderboard.
    recordFailureEvent('1.1.1.1', 'stale@example.com', now()->subDays(3));

    $chart = Livewire::test(TopAttackedEmailsChart::class);
    $data = chartData($chart->instance());

    expect($data['labels'])->toBe(['victim@example.com'])
        ->and($data['datasets'][0]['data'])->toBe([3]);
});

it('aggregates the top source ips across attacked emails', function () {
    recordFailureEvent('1.1.1.1', 'a@example.com', now()->subHour());
    recordFailureEvent('1.1.1.1', 'b@example.com', now()->subHour());
    recordFailureEvent('2.2.2.2', 'a@example.com', now()->subHour());

    $chart = Livewire::test(TopSourceIpsChart::class);
    $data = chartData($chart->instance());

    expect($data['labels'])->toBe(['1.1.1.1', '2.2.2.2'])
        ->and($data['datasets'][0]['data'])->toBe([2, 1]);
});

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
