<?php

use Carbon\Carbon;
use Filament\Actions\ExportAction;
use Filament\Actions\Exports\Enums\ExportFormat;
use Filament\Actions\Exports\Models\Export;
use Filament\Facades\Filament;
use Filament\Panel;
use Illuminate\Support\Facades\Storage;
use Livewire\Livewire;
use SolutionForest\FilamentLoginGuard\Filament\Exports\LoginAttemptExporter;
use SolutionForest\FilamentLoginGuard\Filament\Exports\UserSessionExporter;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Models\UserSession;
use SolutionForest\FilamentLoginGuard\Pages\LoginGuard;
use SolutionForest\FilamentLoginGuard\Pages\UserSessions;
use Workbench\Database\Factories\UserFactory;

beforeEach(function () {
    Carbon::setTestNow('2026-01-01 00:00:00');

    $panel = Panel::make()
        ->id('admin')
        ->default()
        ->plugin(FilamentLoginGuardPlugin::make());

    Filament::registerPanel($panel);
    Filament::setCurrentPanel($panel);

    // The export flow persists an Export row with a real Eloquent user
    // relation, so a database-backed user is required here (TestUser is not
    // an Eloquent model).
    $this->actingAs(UserFactory::new()->create());

    // Run the export queue synchronously and capture the CSV on a fake disk.
    config()->set('queue.default', 'sync');
    Storage::fake('filament');

    UserSession::query()->create([
        'id' => str_repeat('b', 40),
        'user_id' => 1,
        'ip_address' => '1.2.3.4',
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);
});

afterEach(function () {
    Carbon::setTestNow(null);
});

/** The Export model has no factory; create rows directly. */
function makeExport(array $attributes = []): Export
{
    return Export::query()->create(array_merge([
        'file_disk' => 'filament',
        'exporter' => LoginAttemptExporter::class,
        'total_rows' => 0,
        'user_id' => 1,
    ], $attributes));
}

it('only offers csv as the export format', function () {
    $attemptExporter = new LoginAttemptExporter(makeExport(), [], []);
    $sessionExporter = new UserSessionExporter(makeExport(), [], []);

    expect($attemptExporter->getFormats())->toBe([ExportFormat::Csv])
        ->and($sessionExporter->getFormats())->toBe([ExportFormat::Csv]);
});

it('exports login attempts as csv with sanitized values', function () {
    // A crafted email that would become a formula in spreadsheet software.
    LoginAttempt::factory()->create([
        'ip' => '9.9.9.9',
        'email' => '=HYPERLINK("http://evil.com")',
        'attempts' => 3,
        'lockout_count' => 1,
        'window_started_at' => now(),
    ]);

    $export = makeExport(['exporter' => LoginAttemptExporter::class]);

    $exporter = $export->getExporter(
        columnMap: ['ip' => 'IP', 'email' => 'Email', 'device_name' => 'Device', 'attempts' => 'Attempts', 'lockout_count' => 'Lockouts', 'locked_until' => 'Locked until', 'last_attempt_at' => 'Last attempt', 'success_count' => 'Successful', 'last_success_at' => 'Last success'],
        options: [],
    );

    $rows = [];
    foreach (LoginAttempt::query()->lazy() as $record) {
        $rows[] = $exporter($record);
    }

    expect(count($rows))->toBe(1)
        ->and($rows[0][0])->toBe('9.9.9.9')
        // The formula injection must be neutralized.
        ->and($rows[0][1])->toStartWith("'")
        ->and($rows[0][3])->toBe('3')
        ->and($rows[0][4])->toBe('1');
});

it('exports user sessions with device and last active data', function () {
    UserSession::query()->create([
        'id' => str_repeat('c', 40),
        'user_id' => 1,
        'ip_address' => '5.6.7.8',
        'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
        'payload' => 'test',
        'last_activity' => now()->subMinutes(3)->timestamp,
    ]);

    $export = makeExport(['exporter' => UserSessionExporter::class]);

    $exporter = $export->getExporter(
        columnMap: ['user_email' => 'User', 'ip_address' => 'IP', 'device_name' => 'Device', 'last_active_at' => 'Last active', 'is_new_device' => 'New device'],
        options: [],
    );

    $rows = [];
    foreach (UserSession::query()->whereNotNull('user_id')->lazy() as $record) {
        $rows[] = $exporter($record);
    }

    expect(count($rows))->toBe(2)
        ->and($rows[0][1])->toBe('1.2.3.4')
        ->and($rows[1][1])->toBe('5.6.7.8')
        ->and($rows[1][2])->toBe('Chrome on macOS');
});

it('offers the export action on both admin pages', function () {
    Livewire::test(LoginGuard::class)
        ->assertSuccessful()
        ->assertSeeText(__('filament-loginguard::loginguard.export.action'));

    Livewire::test(UserSessions::class)
        ->assertSuccessful()
        ->assertSeeText(__('filament-loginguard::loginguard.export.action'));
});

it('registers the export action as a page header action, not a table header action', function () {
    $page = Livewire::test(LoginGuard::class)->instance();

    expect(collect($page->getCachedHeaderActions())->every(fn ($action) => $action instanceof ExportAction))->toBeTrue()
        ->and($page->getTable()->getHeaderActions())->toBeEmpty();
});

it('hides the export action when disabled per page', function () {
    config()->set('filament-loginguard.pages.attempts.export', false);
    config()->set('filament-loginguard.pages.sessions.export', false);

    LoginAttempt::factory()->create();

    Livewire::test(LoginGuard::class)
        ->assertSuccessful()
        ->assertDontSeeText(__('filament-loginguard::loginguard.export.action'));

    Livewire::test(UserSessions::class)
        ->assertSuccessful()
        ->assertDontSeeText(__('filament-loginguard::loginguard.export.action'));
});

it('runs the attempts export end-to-end and writes the csv file', function () {
    LoginAttempt::factory()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'attempts' => 5,
        'window_started_at' => now(),
    ]);

    Livewire::test(LoginGuard::class)
        ->callAction('export', data: [
            'columnMap' => [
                'ip' => ['isEnabled' => true, 'label' => 'IP'],
                'email' => ['isEnabled' => true, 'label' => 'Email'],
                'device_name' => ['isEnabled' => true, 'label' => 'Device'],
                'attempts' => ['isEnabled' => true, 'label' => 'Attempts'],
                'lockout_count' => ['isEnabled' => true, 'label' => 'Lockouts'],
                'locked_until' => ['isEnabled' => true, 'label' => 'Locked until'],
                'last_attempt_at' => ['isEnabled' => true, 'label' => 'Last attempt'],
                'success_count' => ['isEnabled' => true, 'label' => 'Successful'],
                'last_success_at' => ['isEnabled' => true, 'label' => 'Last success'],
            ],
        ])
        ->assertHasNoActionErrors();

    $export = Export::query()->sole();

    expect($export->exporter)->toBe(LoginAttemptExporter::class)
        ->and($export->total_rows)->toBe(1);

    // With the sync queue the batch finished immediately: rows were processed.
    expect($export->processed_rows)->toBe(1)
        ->and($export->successful_rows)->toBe(1);
});
