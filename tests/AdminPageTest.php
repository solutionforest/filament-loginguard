<?php

use Carbon\Carbon;
use Filament\Facades\Filament;
use Filament\Panel;
use Filament\Widgets\WidgetConfiguration;
use Illuminate\Support\Facades\Gate;
use Livewire\Livewire;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;
use SolutionForest\FilamentLoginGuard\LoginGuardService;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Models\LoginGuardLock;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;
use SolutionForest\FilamentLoginGuard\Pages\LoginGuard;
use SolutionForest\FilamentLoginGuard\Tests\Support\TestCluster;
use SolutionForest\FilamentLoginGuard\Tests\Support\TestUser;
use SolutionForest\FilamentLoginGuard\Widgets\FailureTrendChart;
use SolutionForest\FilamentLoginGuard\Widgets\LoginGuardStats;
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

it('renders the blocked attempts page', function () {
    LoginAttempt::factory()->locked()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
    ]);

    Livewire::test(LoginGuard::class)
        ->assertSuccessful()
        ->assertSee('1.2.3.4')
        ->assertSee('Chrome on macOS')
        ->assertDontSee('Lockouts');
});

it('shows the remaining lock time as a relative string', function () {
    $record = LoginAttempt::factory()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'attempts' => 3,
    ]);

    LoginGuardLock::query()->create([
        'scope_type' => 'ip',
        'scope_key' => '1.2.3.4',
        'locked_until' => now()->addMinutes(15),
        'escalation_count' => 1,
    ]);

    Livewire::test(LoginGuard::class)
        ->assertSuccessful()
        ->assertSee('15 minutes from now');
});

it('shows the last attempt time as a relative string', function () {
    LoginAttempt::factory()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'last_attempt_at' => now()->subMinutes(15),
    ]);

    Livewire::test(LoginGuard::class)
        ->assertSuccessful()
        ->assertSee('15 minutes ago');
});

it('parses user agents into device names', function () {
    $record = LoginAttempt::factory()->create([
        'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
    ]);

    expect($record->device_name)->toBe('Chrome on macOS');

    $record->update(['user_agent' => null]);

    expect($record->device_name)->toBeNull();
});

it('can unblock a record', function () {
    $record = LoginAttempt::factory()->locked(lockedUntil: now()->addMinutes(15))->create();

    Livewire::test(LoginGuard::class)
        ->callTableAction('unblock', $record);

    $service = app(LoginGuardService::class);

    expect($service->isLocked($record->ip, $record->email))->toBeFalse()
        ->and(LoginGuardLock::query()->where('scope_type', 'ip')->where('scope_key', $record->ip)->exists())->toBeFalse()
        ->and(LoginGuardLock::query()->where('scope_type', 'email')->where('scope_key', $record->email)->exists())->toBeFalse();
});

it('only offers unblock for locked records', function () {
    $locked = LoginAttempt::factory()->locked(lockedUntil: now()->addMinutes(15))->create();
    $tracked = LoginAttempt::factory()->create(['attempts' => 2]);

    Livewire::test(LoginGuard::class)
        ->assertTableActionVisible('unblock', $locked)
        ->assertTableActionHidden('unblock', $tracked);
});

it('offers no delete action for records', function () {
    LoginAttempt::factory()->locked()->create();

    Livewire::test(LoginGuard::class)
        ->assertSuccessful()
        ->assertActionDoesNotExist('delete');
});

it('denies access when the admin page is disabled', function () {
    config()->set('filament-loginguard.pages.attempts.enabled', false);

    Livewire::test(LoginGuard::class)
        ->assertStatus(403);
});

it('gates the page behind an ability when configured', function () {
    config()->set('filament-loginguard.pages.attempts.authorize', 'view-filament-loginguard');

    Gate::define('view-filament-loginguard', fn (): bool => false);

    Livewire::test(LoginGuard::class)
        ->assertStatus(403);

    Gate::define('view-filament-loginguard', fn (): bool => true);

    Livewire::test(LoginGuard::class)->assertSuccessful();
});

it('uses the view-specific ability ahead of the legacy attempts ability', function () {
    config()->set('filament-loginguard.pages.attempts.authorize', 'manage-attempts');
    config()->set('filament-loginguard.pages.attempts.authorize_view', 'view-attempts');
    config()->set('filament-loginguard.pages.attempts.authorize_unblock', 'unblock-attempts');
    Gate::define('manage-attempts', fn (): bool => true);
    Gate::define('unblock-attempts', fn (): bool => true);

    Livewire::test(LoginGuard::class)->assertStatus(403);

    Gate::define('view-attempts', fn (): bool => true);

    Livewire::test(LoginGuard::class)->assertSuccessful();
});

it('enforces the separate unblock ability for individual and bulk actions', function (bool $defineDeniedAbility) {
    config()->set('filament-loginguard.pages.attempts.authorize', 'manage-attempts');
    config()->set('filament-loginguard.pages.attempts.authorize_view', 'view-attempts');
    config()->set('filament-loginguard.pages.attempts.authorize_unblock', 'unblock-attempts');
    Gate::define('manage-attempts', fn (): bool => true);
    Gate::define('view-attempts', fn (): bool => true);

    if ($defineDeniedAbility) {
        Gate::define('unblock-attempts', fn (): bool => false);
    }

    $first = LoginAttempt::factory()->locked(ip: '1.2.3.4', email: 'a@example.com', lockedUntil: now()->addMinutes(15))->create();
    $second = LoginAttempt::factory()->locked(ip: '5.6.7.8', email: 'b@example.com', lockedUntil: now()->addMinutes(15))->create();
    $service = app(LoginGuardService::class);

    Livewire::test(LoginGuard::class)
        ->assertCanSeeTableRecords([$first, $second])
        ->assertTableActionHidden('unblock', $first)
        ->assertTableBulkActionHidden('unblockMany')
        ->mountTableAction('unblock', $first)
        ->assertActionNotMounted('unblock')
        ->mountTableBulkAction('unblockMany', [$first, $second])
        ->assertActionNotMounted('unblockMany');

    expect($service->isLocked($first->ip, $first->email))->toBeTrue()
        ->and($service->isLocked($second->ip, $second->email))->toBeTrue();

    Gate::define('unblock-attempts', fn (): bool => true);

    Livewire::test(LoginGuard::class)
        ->assertTableActionVisible('unblock', $first)
        ->assertTableBulkActionVisible('unblockMany')
        ->callTableAction('unblock', $first);

    expect($service->isLocked($first->ip, $first->email))->toBeFalse()
        ->and($service->isLocked($second->ip, $second->email))->toBeTrue();
})->with([
    'denied gate' => [true],
    'undefined gate' => [false],
]);

it('bulk unblocks selected records across lock scopes and preserves unselected locks', function () {
    $aggregate = LoginAttempt::factory()->locked(ip: '1.2.3.4', email: 'a@example.com', lockedUntil: now()->addMinutes(15))->create();
    $pair = LoginAttempt::factory()->create(['ip' => '5.6.7.8', 'email' => 'b@example.com', 'attempts' => 3]);
    $unselected = LoginAttempt::factory()->locked(ip: '9.9.9.9', email: 'c@example.com', lockedUntil: now()->addMinutes(15))->create();
    LoginGuardLock::query()->create([
        'scope_type' => 'pair',
        'scope_key' => '5.6.7.8|b@example.com',
        'locked_until' => now()->addMinutes(15),
        'escalation_count' => 1,
    ]);

    Livewire::test(LoginGuard::class)
        ->callTableBulkAction('unblockMany', [$aggregate, $pair]);

    $service = app(LoginGuardService::class);

    expect($service->isLocked($aggregate->ip, $aggregate->email))->toBeFalse()
        ->and($service->isLocked($pair->ip, $pair->email))->toBeFalse()
        ->and($service->isLocked($unselected->ip, $unselected->email))->toBeTrue()
        ->and(LoginAttempt::query()->count())->toBe(3)
        ->and(SecurityEvent::query()->where('type', SecurityEvent::TYPE_UNLOCKED)->count())->toBe(3);
});

it('filters attempt rows by active scoped locks and by failed attempts', function () {
    $ipLocked = LoginAttempt::factory()->create(['ip' => '1.2.3.4', 'email' => 'a@example.com', 'attempts' => 1]);
    $emailLocked = LoginAttempt::factory()->create(['ip' => '5.6.7.8', 'email' => 'b@example.com', 'attempts' => 1]);
    $pairLocked = LoginAttempt::factory()->create(['ip' => '9.9.9.9', 'email' => 'c@example.com', 'attempts' => 1]);
    $tracked = LoginAttempt::factory()->create(['ip' => '9.9.9.9', 'email' => 'd@example.com', 'attempts' => 2]);
    $successful = LoginAttempt::factory()->create(['ip' => '6.6.6.6', 'email' => 'e@example.com', 'success_count' => 1]);

    foreach ([
        ['ip', '1.2.3.4', now()->addMinute()],
        ['email', 'b@example.com', now()->addMinute()],
        ['pair', '9.9.9.9|c@example.com', now()->addMinute()],
        ['email', 'd@example.com', now()],
    ] as [$scope, $key, $lockedUntil]) {
        LoginGuardLock::query()->create([
            'scope_type' => $scope,
            'scope_key' => $key,
            'locked_until' => $lockedUntil,
            'escalation_count' => 1,
        ]);
    }

    Livewire::test(LoginGuard::class)
        ->filterTable('status', 'locked')
        ->assertCanSeeTableRecords([$ipLocked, $emailLocked, $pairLocked])
        ->assertCanNotSeeTableRecords([$tracked, $successful])
        ->filterTable('status', 'tracked')
        ->assertCanSeeTableRecords([$ipLocked, $emailLocked, $pairLocked, $tracked])
        ->assertCanNotSeeTableRecords([$successful]);
});

it('orders attempt rows by latest failure and searches by ip or email', function () {
    $oldest = LoginAttempt::factory()->create(['ip' => '1.2.3.4', 'email' => 'old@example.com', 'last_attempt_at' => now()->subMinutes(5)]);
    $newest = LoginAttempt::factory()->create(['ip' => '5.6.7.8', 'email' => 'new@example.com', 'last_attempt_at' => now()]);
    $middle = LoginAttempt::factory()->create(['ip' => '9.9.9.9', 'email' => 'other@example.com', 'last_attempt_at' => now()->subMinute()]);

    Livewire::test(LoginGuard::class)
        ->assertCanSeeTableRecords([$newest, $middle, $oldest], inOrder: true)
        ->searchTable('5.6.7.8')
        ->assertCanSeeTableRecords([$newest])
        ->assertCanNotSeeTableRecords([$middle, $oldest])
        ->searchTable('other@example.com')
        ->assertCanSeeTableRecords([$middle])
        ->assertCanNotSeeTableRecords([$newest, $oldest]);
});

it('hides navigation when disabled', function () {
    config()->set('filament-loginguard.pages.attempts.enabled', false);

    expect(LoginGuard::shouldRegisterNavigation())->toBeFalse();
});

it('hides the stats widget when disabled', function () {
    config()->set('filament-loginguard.pages.attempts.stats_widget', false);

    LoginAttempt::factory()->create();

    // The widgets are lazy Livewire components; their content is not part of
    // the page HTML, so assert the widget registration instead.
    $widgets = Livewire::test(LoginGuard::class)->instance()->getVisibleHeaderWidgets();

    expect(collect($widgets)->map(fn ($widget) => $widget instanceof WidgetConfiguration ? $widget->widget : $widget)->all())
        ->not->toContain(LoginGuardStats::class);
});

it('registers the stats widget by default', function () {
    LoginAttempt::factory()->create();

    $widgets = collect(Livewire::test(LoginGuard::class)->instance()->getVisibleHeaderWidgets())
        ->map(fn ($widget) => $widget instanceof WidgetConfiguration ? $widget->widget : $widget)
        ->all();

    expect($widgets)->toContain(LoginGuardStats::class);
});

it('hides the charts when disabled but keeps the stats widget', function () {
    config()->set('filament-loginguard.pages.attempts.charts', false);

    LoginAttempt::factory()->create();

    $widgets = collect(Livewire::test(LoginGuard::class)->instance()->getVisibleHeaderWidgets())
        ->map(fn ($widget) => $widget instanceof WidgetConfiguration ? $widget->widget : $widget)
        ->all();

    expect($widgets)->toContain(LoginGuardStats::class)
        ->not->toContain(FailureTrendChart::class)
        ->not->toContain(TopAttackedEmailsChart::class)
        ->not->toContain(TopSourceIpsChart::class);
});

it('nests under a cluster when configured', function () {
    expect(LoginGuard::getCluster())->toBeNull();

    config()->set('filament-loginguard.pages.attempts.cluster', TestCluster::class);

    expect(LoginGuard::getCluster())->toBe(TestCluster::class);

    config()->set('filament-loginguard.pages.attempts.cluster', 'Not\\A\\Cluster');

    expect(LoginGuard::getCluster())->toBeNull();
});

it('shows the country badge (not ASN) on the attempts table', function () {
    LoginAttempt::factory()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
    ]);

    SecurityEvent::query()->create([
        'type' => SecurityEvent::TYPE_LOGIN_FAILED,
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'occurred_at' => now(),
        'metadata' => ['country' => 'US', 'asn' => 7922],
    ]);

    Livewire::test(LoginGuard::class)
        ->assertSuccessful()
        ->assertSee('US')
        ->assertDontSee('7922');
});

it('resolves the latest located event for the country badge', function () {
    $attempt = LoginAttempt::factory()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
    ]);

    SecurityEvent::query()->create([
        'type' => SecurityEvent::TYPE_LOGIN_FAILED,
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'occurred_at' => now()->subMinutes(10),
        'metadata' => ['country' => 'US'],
    ]);

    SecurityEvent::query()->create([
        'type' => SecurityEvent::TYPE_LOGIN_FAILED,
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'occurred_at' => now(),
        'metadata' => ['country' => 'GB', 'asn' => 13335],
    ]);

    $resolved = LoginAttempt::query()->with('latestLocatedEvent')->findOrFail($attempt->id);

    expect($resolved->latestLocatedEvent?->metadata)->toBe(['country' => 'GB', 'asn' => 13335]);
});

it('resolves no located event when the IP has no location metadata', function () {
    $attempt = LoginAttempt::factory()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
    ]);

    $resolved = LoginAttempt::query()->with('latestLocatedEvent')->findOrFail($attempt->id);

    expect($resolved->latestLocatedEvent)->toBeNull();
});
