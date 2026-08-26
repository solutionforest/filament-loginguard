<?php

use Illuminate\Console\Scheduling\Schedule;

function scheduledCommands(): array
{
    return collect(app(Schedule::class)->events())
        ->map(fn ($event) => $event->command)
        ->all();
}

function scheduledExpression(string $needle): ?string
{
    return collect(app(Schedule::class)->events())
        ->first(fn ($event) => str_contains($event->command, $needle))?->expression;
}

function scheduledWithoutOverlapping(string $needle): bool
{
    $event = collect(app(Schedule::class)->events())
        ->first(fn ($event) => str_contains($event->command, $needle));

    return $event?->withoutOverlapping ?? false;
}

it('does not schedule cleanup commands by default', function () {
    config()->set('filament-loginguard.maintenance.cleanup_attempts.enabled', false);
    config()->set('filament-loginguard.maintenance.cleanup_sessions.enabled', false);

    $commands = collect(scheduledCommands());

    expect($commands->contains(fn (string $command) => str_contains($command, 'filament-loginguard:cleanup')))
        ->toBeFalse();
});

it('schedules the attempt cleanup with the default cron expression', function () {
    config()->set('filament-loginguard.maintenance.cleanup_attempts.enabled', true);

    $commands = collect(scheduledCommands());

    expect($commands->contains(fn (string $command) => str_contains($command, 'filament-loginguard:cleanup-attempts')))
        ->toBeTrue();

    expect($commands->contains(fn (string $command) => str_contains($command, 'filament-loginguard:cleanup-sessions')))
        ->toBeFalse();

    expect(scheduledExpression('filament-loginguard:cleanup-attempts'))->toBe('0 0 * * *')
        ->and(scheduledWithoutOverlapping('filament-loginguard:cleanup-attempts'))->toBeTrue();
});

it('respects a custom cron expression', function () {
    config()->set('filament-loginguard.maintenance.cleanup_attempts.enabled', true);
    config()->set('filament-loginguard.maintenance.cleanup_attempts.expression', '*/15 * * * *');

    expect(scheduledExpression('filament-loginguard:cleanup-attempts'))->toBe('*/15 * * * *');
});

it('schedules the sessions cleanup only with database sessions', function () {
    config()->set('filament-loginguard.maintenance.cleanup_sessions.enabled', true);
    config()->set('session.driver', 'database');

    expect(scheduledExpression('filament-loginguard:cleanup-sessions'))->toBe('0 * * * *')
        ->and(scheduledWithoutOverlapping('filament-loginguard:cleanup-sessions'))->toBeTrue();
});

it('does not schedule the sessions cleanup when sessions are not database-driven', function () {
    config()->set('filament-loginguard.maintenance.cleanup_sessions.enabled', true);
    config()->set('session.driver', 'file');

    $commands = collect(scheduledCommands());

    expect($commands->contains(fn (string $command) => str_contains($command, 'filament-loginguard:cleanup-sessions')))
        ->toBeFalse();
});
