<?php

use Carbon\Carbon;
use Filament\Facades\Filament;
use Filament\Panel;
use Filament\Widgets\WidgetConfiguration;
use Livewire\Livewire;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
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

it('charts the daily failure trend inside the selected window', function () {
    // Two failures on a day inside the range, and one stale row outside it.
    LoginAttempt::query()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'attempts' => 2,
        'window_started_at' => now()->subDays(2),
    ]);
    LoginAttempt::query()->create([
        'ip' => '1.2.3.4',
        'email' => 'b@example.com',
        'attempts' => 5,
        'window_started_at' => now()->subDays(40),
    ]);

    $chart = Livewire::test(FailureTrendChart::class, ['filter' => '30']);
    $data = chartData($chart->instance());

    $values = $data['datasets'][0]['data'];

    // 30 labels (one per day), the stale row is not counted, the fresh row's
    // 2 attempts appear two days ago.
    expect(count($data['labels']))->toBe(30)
        ->and(array_sum($values))->toBe(2)
        ->and($values[count($values) - 3])->toBe(2);
});

it('limits the trend to 7 days with the filter', function () {
    LoginAttempt::query()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'attempts' => 1,
        'window_started_at' => now()->subDays(10),
    ]);

    $chart = Livewire::test(FailureTrendChart::class, ['filter' => '7']);
    $data = chartData($chart->instance());

    expect(count($data['labels']))->toBe(7)
        ->and(array_sum($data['datasets'][0]['data']))->toBe(0);
});

it('ignores invalid filter values', function () {
    LoginAttempt::query()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'attempts' => 1,
        'window_started_at' => now()->subDays(10),
    ]);

    $chart = Livewire::test(FailureTrendChart::class, ['filter' => '999']);
    $data = chartData($chart->instance());

    // Falls back to 30 days, so the 10-day-old failure is included.
    expect(count($data['labels']))->toBe(30)
        ->and(array_sum($data['datasets'][0]['data']))->toBe(1);
});

it('ranks the top attacked emails with windowed attempts', function () {
    LoginAttempt::query()->create([
        'ip' => '1.2.3.4',
        'email' => 'hot@example.com',
        'attempts' => 9,
        'window_started_at' => now()->subHour(),
    ]);
    LoginAttempt::query()->create([
        'ip' => '1.2.3.4',
        'email' => 'cold@example.com',
        'attempts' => 3,
        'window_started_at' => now()->subHour(),
    ]);
    LoginAttempt::query()->create([
        'ip' => '1.2.3.4',
        'email' => 'stale@example.com',
        'attempts' => 50,
        'window_started_at' => now()->subDays(3),
    ]);

    $chart = Livewire::test(TopAttackedEmailsChart::class);
    $data = chartData($chart->instance());

    expect($data['labels'])->toBe(['hot@example.com', 'cold@example.com'])
        ->and($data['datasets'][0]['data'])->toBe([9, 3]);
});

it('ranks the top source ips with windowed attempts', function () {
    LoginAttempt::query()->create([
        'ip' => '9.9.9.9',
        'email' => 'a@example.com',
        'attempts' => 7,
        'window_started_at' => now()->subHour(),
    ]);
    LoginAttempt::query()->create([
        'ip' => '1.2.3.4',
        'email' => 'b@example.com',
        'attempts' => 2,
        'window_started_at' => now()->subHour(),
    ]);

    $chart = Livewire::test(TopSourceIpsChart::class);
    $data = chartData($chart->instance());

    expect($data['labels'])->toBe(['9.9.9.9', '1.2.3.4'])
        ->and($data['datasets'][0]['data'])->toBe([7, 2]);
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
