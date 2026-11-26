<?php

use Carbon\Carbon;
use Filament\Actions\ExportAction;
use Filament\Actions\Exports\Enums\ExportFormat;
use Filament\Actions\Exports\Models\Export;
use Filament\Facades\Filament;
use Filament\Panel;
use Illuminate\Support\Facades\Storage;
use Illuminate\Testing\TestResponse;
use League\Csv\Reader;
use League\Csv\Writer;
use Livewire\Livewire;
use SolutionForest\FilamentLoginGuard\Filament\Exports\LoginAttemptExporter;
use SolutionForest\FilamentLoginGuard\Filament\Exports\UserSessionExporter;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;
use SolutionForest\FilamentLoginGuard\Models\KnownDevice;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Models\LoginGuardLock;
use SolutionForest\FilamentLoginGuard\Models\UserSession;
use SolutionForest\FilamentLoginGuard\Pages\LoginGuard;
use SolutionForest\FilamentLoginGuard\Pages\UserSessions;
use Workbench\App\Models\User;
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
    $this->operator = UserFactory::new()->create();
    $this->actingAs($this->operator);

    // Run the export queue synchronously and capture the CSV on a fake disk.
    config()->set('queue.default', 'sync');
    config()->set('filament.default_filesystem_disk', 'filament');
    config()->set('filament-loginguard.sessions.user_model', User::class);
    Storage::fake('filament');
});

afterEach(function () {
    Carbon::setTestNow(null);
});

function exportColumnMap(array $columns): array
{
    return ['columnMap' => array_map(fn (string $label): array => ['isEnabled' => true, 'label' => $label], $columns)];
}

function readExportedCsv(TestResponse $response): array
{
    $content = $response->assertOk()->assertHeader('Content-Type', 'text/csv; charset=UTF-8')->streamedContent();

    return iterator_to_array(Reader::fromString($content)->getRecords(), preserve_keys: false);
}

it('only offers csv as the export format', function () {
    $attemptExporter = new LoginAttemptExporter(new Export, [], []);
    $sessionExporter = new UserSessionExporter(new Export, [], []);

    expect($attemptExporter->getFormats())->toBe([ExportFormat::Csv])
        ->and($sessionExporter->getFormats())->toBe([ExportFormat::Csv]);
});

it('offers the export action on both admin pages', function () {
    Livewire::test(LoginGuard::class)
        ->assertSuccessful()
        ->assertSeeText(__('filament-loginguard::loginguard.export.action'));

    Livewire::test(UserSessions::class)
        ->assertSuccessful()
        ->assertSeeText(__('filament-loginguard::loginguard.export.action'));
});

it('registers the export action in the page header', function () {
    $page = Livewire::test(LoginGuard::class)->instance();

    expect(collect($page->getCachedHeaderActions())->contains(fn ($action) => $action instanceof ExportAction))->toBeTrue()
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

it('neutralizes formula-looking device and address display values in CSV', function () {
    $attempt = new class(['ip' => '+address label']) extends LoginAttempt
    {
        public function getDeviceNameAttribute(): ?string
        {
            return '=device label';
        }
    };
    $session = new class(['ip_address' => '+address label']) extends UserSession
    {
        public function getDeviceNameAttribute(): ?string
        {
            return '=device label';
        }
    };
    $attemptExporter = new LoginAttemptExporter(new Export, ['ip' => 'IP', 'device_name' => 'Device'], []);
    $sessionExporter = new UserSessionExporter(new Export, ['ip_address' => 'IP', 'device_name' => 'Device'], []);

    $csv = Writer::fromString();
    $csv->insertOne($attemptExporter($attempt));
    $csv->insertOne($sessionExporter($session));

    expect(iterator_to_array(Reader::fromString($csv->toString())->getRecords(), preserve_keys: false))
        ->toBe([
            ["'+address label", "'=device label"],
            ["'+address label", "'=device label"],
        ]);
});

it('downloads attempts as CSV with the effective lock expiry and neutralized email', function () {
    $formula = '=HYPERLINK("https://example.test/a,b")';

    LoginAttempt::factory()->create([
        'ip' => '1.2.3.4',
        'email' => $formula,
        'attempts' => 5,
        'lockout_count' => 2,
        'last_attempt_at' => now()->subMinutes(5),
        'success_count' => 3,
        'last_success_at' => now()->subMinutes(6),
    ]);
    LoginAttempt::factory()->create([
        'ip' => '1.2.3.4',
        'email' => 'neighbor@example.com',
        'last_attempt_at' => now()->subMinutes(10),
    ]);
    LoginAttempt::factory()->create([
        'ip' => '5.6.7.8',
        'email' => $formula,
        'last_attempt_at' => now()->subMinutes(15),
    ]);
    LoginAttempt::factory()->create([
        'ip' => '9.9.9.9',
        'email' => 'expired@example.com',
        'last_attempt_at' => now()->subMinutes(20),
        'locked_until' => now()->addHour(),
    ]);

    foreach ([
        [LoginGuardLock::SCOPE_IP, '1.2.3.4', now()->addMinutes(10)],
        [LoginGuardLock::SCOPE_EMAIL, $formula, now()->addMinutes(15)],
        [LoginGuardLock::SCOPE_PAIR, '1.2.3.4|' . $formula, now()->addMinutes(25)],
        [LoginGuardLock::SCOPE_IP, '9.9.9.9', now()],
    ] as [$scope, $key, $expiresAt]) {
        LoginGuardLock::query()->create([
            'scope_type' => $scope,
            'scope_key' => $key,
            'locked_until' => $expiresAt,
        ]);
    }

    Livewire::test(LoginGuard::class)
        ->callAction('export', data: exportColumnMap([
            'ip' => 'IP',
            'email' => 'Email',
            'device_name' => 'Device',
            'attempts' => 'Attempts',
            'lockout_count' => 'Lockouts',
            'locked_until' => 'Locked until',
            'last_attempt_at' => 'Last attempt',
            'success_count' => 'Successful',
            'last_success_at' => 'Last success',
        ]))
        ->assertHasNoActionErrors();

    $export = Export::query()->sole();
    $response = $this->actingAs($this->operator)->get(route('filament.exports.download', ['export' => $export, 'format' => 'csv']));

    expect($export->exporter)->toBe(LoginAttemptExporter::class)
        ->and($export->total_rows)->toBe(4)
        ->and($export->processed_rows)->toBe(4)
        ->and($export->successful_rows)->toBe(4)
        ->and(readExportedCsv($response))->toBe([
            ['IP', 'Email', 'Device', 'Attempts', 'Lockouts', 'Locked until', 'Last attempt', 'Successful', 'Last success'],
            ['1.2.3.4', "'" . $formula, '', '5', '2', '2026-01-01 00:25:00', '2025-12-31 23:55:00', '3', '2025-12-31 23:54:00'],
            ['1.2.3.4', 'neighbor@example.com', '', '0', '0', '2026-01-01 00:10:00', '2025-12-31 23:50:00', '0', ''],
            ['5.6.7.8', "'" . $formula, '', '0', '0', '2026-01-01 00:15:00', '2025-12-31 23:45:00', '0', ''],
            ['9.9.9.9', 'expired@example.com', '', '0', '0', '', '2025-12-31 23:40:00', '0', ''],
        ]);

    $response->assertDownload("login-attempts-{$export->getKey()}.csv");
});

it('downloads the searched signed-in sessions with device details and neutralized email', function () {
    $account = UserFactory::new()->create(['email' => '+SAMPLE@example.com']);

    UserSession::query()->create([
        'id' => str_repeat('b', 40),
        'user_id' => $this->operator->getKey(),
        'ip_address' => '1.2.3.4',
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);
    UserSession::query()->create([
        'id' => str_repeat('c', 40),
        'user_id' => $account->getKey(),
        'ip_address' => '5.6.7.8',
        'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
        'payload' => 'private',
        'last_activity' => now()->subMinutes(3)->timestamp,
    ]);
    UserSession::query()->create([
        'id' => str_repeat('g', 40),
        'ip_address' => '5.6.7.8',
        'payload' => 'guest',
        'last_activity' => now()->timestamp,
    ]);
    KnownDevice::query()->create([
        'user_id' => $account->getKey(),
        'fingerprint' => 'Chrome on macOS',
        'first_seen_at' => now()->subMinutes(3),
    ]);

    Livewire::test(UserSessions::class)
        ->searchTable('5.6.7.8')
        ->callAction('export', data: exportColumnMap([
            'user_email' => 'User',
            'ip_address' => 'IP',
            'device_name' => 'Device',
            'last_active_at' => 'Last active',
            'is_new_device' => 'New device',
        ]))
        ->assertHasNoActionErrors();

    $export = Export::query()->sole();
    $response = $this->actingAs($this->operator)->get(route('filament.exports.download', ['export' => $export, 'format' => 'csv']));

    expect($export->exporter)->toBe(UserSessionExporter::class)
        ->and($export->total_rows)->toBe(1)
        ->and($export->processed_rows)->toBe(1)
        ->and($export->successful_rows)->toBe(1)
        ->and(readExportedCsv($response))->toBe([
            ['User', 'IP', 'Device', 'Last active', 'New device'],
            ["'+SAMPLE@example.com", '5.6.7.8', 'Chrome on macOS', '2025-12-31 23:57:00', '1'],
        ]);

    $response->assertDownload("user-sessions-{$export->getKey()}.csv");
});
