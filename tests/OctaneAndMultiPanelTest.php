<?php

use Filament\Facades\Filament;
use Filament\Panel;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;
use SolutionForest\FilamentLoginGuard\Models\Device;
use SolutionForest\FilamentLoginGuard\Models\DeviceSession;
use SolutionForest\FilamentLoginGuard\Pages\LoginGuard;
use SolutionForest\FilamentLoginGuard\Pages\MyDevices;
use SolutionForest\FilamentLoginGuard\Pages\UserSessions;
use SolutionForest\FilamentLoginGuard\Services\DeviceManager;
use SolutionForest\FilamentLoginGuard\Services\MaxmindIpIntelligence;
use SolutionForest\FilamentLoginGuard\Support\AuthorizesPages;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;

it('does not leak pages or user menu items onto panels that do not register FilamentLoginGuardPlugin', function (): void {
    /** @var User $user */
    $user = UserFactory::new()->create();
    $this->actingAs($user);

    Route::post('/guard-admin/logout', fn () => 'ok')->name('filament.guard-admin.auth.logout');
    Route::post('/plain-portal/logout', fn () => 'ok')->name('filament.plain-portal.auth.logout');

    $adminPanel = Panel::make()
        ->id('guard-admin')
        ->path('guard-admin')
        ->default()
        ->plugin(FilamentLoginGuardPlugin::make());

    $plainPanel = Panel::make()
        ->id('plain-portal')
        ->path('plain-portal');

    Filament::registerPanel($adminPanel);
    Filament::registerPanel($plainPanel);

    Filament::setCurrentPanel($plainPanel);
    Filament::bootCurrentPanel();

    expect(FilamentLoginGuardPlugin::current())->toBeNull()
        ->and($plainPanel->getPages())->not->toContain(LoginGuard::class)
        ->and($plainPanel->getPages())->not->toContain(MyDevices::class)
        ->and($plainPanel->getUserMenuItems())->not->toHaveKey('filament-loginguard-my-devices');

    Filament::setCurrentPanel($adminPanel);
    Filament::bootCurrentPanel();

    expect(FilamentLoginGuardPlugin::current())->toBeInstanceOf(FilamentLoginGuardPlugin::class)
        ->and($adminPanel->getPages())->toContain(LoginGuard::class, UserSessions::class, MyDevices::class)
        ->and($adminPanel->getUserMenuItems())->toHaveKey('filament-loginguard-my-devices');
});

it('supports per-panel page toggles and per-panel authorization callbacks across multiple panels', function (): void {
    /** @var User $superAdmin */
    $superAdmin = UserFactory::new()->create(['email' => 'super@example.test']);
    /** @var User $editor */
    $editor = UserFactory::new()->create(['email' => 'editor@example.test']);

    $opsPanel = Panel::make()
        ->id('ops')
        ->path('ops')
        ->default()
        ->plugin(
            FilamentLoginGuardPlugin::make()
                ->loginGuardPage(true)
                ->userSessionsPage(false)
                ->myDevicesPage(true, userMenu: true)
                ->authorizeAttemptsUsing(fn (Authenticatable $user): bool => $user->getAuthIdentifier() === $superAdmin->id),
        );

    $memberPanel = Panel::make()
        ->id('member')
        ->path('member')
        ->plugin(
            FilamentLoginGuardPlugin::make()
                ->loginGuardPage(false)
                ->userSessionsPage(false)
                ->myDevicesPage(true, userMenu: false),
        );

    Filament::registerPanel($opsPanel);
    Filament::registerPanel($memberPanel);

    // Ops panel: has LoginGuard + MyDevices, no UserSessions, gated to superAdmin.
    Filament::setCurrentPanel($opsPanel);
    $this->actingAs($editor);
    expect(LoginGuard::canAccess())->toBeFalse()
        ->and(AuthorizesPages::canUnblockAttempts())->toBeFalse()
        ->and(UserSessions::canAccess())->toBeFalse()
        ->and(MyDevices::canAccess())->toBeTrue();

    $this->actingAs($superAdmin);
    expect(LoginGuard::canAccess())->toBeTrue()
        ->and(AuthorizesPages::canUnblockAttempts())->toBeTrue();

    // Member panel: MyDevices only, no LoginGuard, user menu item hidden from visible items.
    Route::post('/member/logout', fn () => 'ok')->name('filament.member.auth.logout');
    Filament::setCurrentPanel($memberPanel);
    expect($memberPanel->getPages())->toBe([MyDevices::class])
        ->and(LoginGuard::canAccess())->toBeFalse()
        ->and(MyDevices::canAccess())->toBeTrue()
        ->and($memberPanel->getUserMenuItems())->not->toHaveKey('filament-loginguard-my-devices');
});

it('authorizes against the active Filament panel auth guard in multi-guard apps', function (): void {
    config()->set('auth.guards.staff', [
        'driver' => 'session',
        'provider' => 'users',
    ]);

    /** @var User $staffUser */
    $staffUser = UserFactory::new()->create(['email' => 'staff@example.test']);

    $staffPanel = Panel::make()
        ->id('staff-panel')
        ->path('staff')
        ->authGuard('staff')
        ->plugin(
            FilamentLoginGuardPlugin::make()
                ->authorizeAttemptsUsing(fn (Authenticatable $user): bool => $user->getAuthIdentifier() === $staffUser->id),
        );

    Filament::registerPanel($staffPanel);
    Filament::setCurrentPanel($staffPanel);

    // Logged in ONLY on the panel's `staff` guard (default `web` guard is guest).
    Auth::guard('web')->logout();
    Auth::guard('staff')->login($staffUser);

    expect(Auth::user())->toBeNull()
        ->and(AuthorizesPages::canViewAttempts())->toBeTrue()
        ->and(LoginGuard::canAccess())->toBeTrue();
});

it('handles tenant panels safely before a tenant is resolved and never duplicates menu items under Octane', function (): void {
    $tenantModelClass = new class extends Model
    {
        protected $table = 'users';
    };

    $tenantPanel = Panel::make()
        ->id('tenant-admin')
        ->path('tenant-admin')
        ->tenant($tenantModelClass::class)
        ->plugin(FilamentLoginGuardPlugin::make());

    Filament::registerPanel($tenantPanel);
    Filament::setCurrentPanel($tenantPanel);

    // Register dummy tenant-scoped routes to match Filament's runtime route signatures.
    Route::get('/tenant-admin/{tenant}/my-devices', fn () => 'ok')
        ->name('filament.tenant-admin.pages.my-devices');
    Route::post('/tenant-admin/logout', fn () => 'ok')
        ->name('filament.tenant-admin.auth.logout');

    /** @var User $user */
    $user = UserFactory::new()->create();
    $this->actingAs($user);

    // Simulate multiple Octane requests hitting Filament::bootCurrentPanel().
    Filament::bootCurrentPanel();
    Filament::bootCurrentPanel();
    Filament::bootCurrentPanel();

    // Before tenant is resolved (e.g. /login): must not throw UrlGenerationException and stays hidden.
    expect(Filament::getTenant())->toBeNull()
        ->and($tenantPanel->getUserMenuItems())->not->toHaveKey('filament-loginguard-my-devices');

    // Once a tenant is resolved, the menu item becomes visible once (never duplicated) and builds the tenant-scoped URL.
    $tenant = new $tenantModelClass;
    $tenant->forceFill(['id' => 7]);
    Filament::setTenant($tenant);

    $visibleItems = $tenantPanel->getUserMenuItems();
    expect($visibleItems)->toHaveKey('filament-loginguard-my-devices')
        ->and(array_keys(array_filter($visibleItems, static fn (mixed $item, string | int $key): bool => $key === 'filament-loginguard-my-devices', ARRAY_FILTER_USE_BOTH)))
        ->toBe(['filament-loginguard-my-devices'])
        ->and($visibleItems['filament-loginguard-my-devices']->getUrl())->toContain('/tenant-admin/7/my-devices');
});

it('signs out devices cleanly on non-database session drivers (e.g. Redis/Valkey/array) without touching a sessions table', function (): void {
    config()->set('session.driver', 'array');

    /** @var User $user */
    $user = UserFactory::new()->create();

    $device = Device::query()->create([
        'guard' => 'web',
        'user_type' => $user::class,
        'user_identifier' => (string) $user->id,
        'token_hash' => hash('sha256', 'token-non-db'),
        'device_name' => 'Chrome on macOS',
        'first_seen_at' => now(),
        'last_seen_at' => now(),
    ]);

    DeviceSession::query()->create([
        'device_id' => $device->id,
        'guard' => 'web',
        'session_id' => 'remote-session-1',
        'last_seen_at' => now(),
    ]);

    $manager = app(DeviceManager::class);

    $signedOut = $manager->signOutDevice($device, 'current-session');
    expect($signedOut)->toBe(1)
        ->and(DeviceSession::query()->where('session_id', 'remote-session-1')->exists())->toBeFalse();

    DeviceSession::query()->create([
        'device_id' => $device->id,
        'guard' => 'web',
        'session_id' => 'remote-session-2',
        'last_seen_at' => now(),
    ]);

    $signedOutOthers = $manager->signOutOthers($user, 'web', $user::class, (string) $user->id, 'current-session');
    expect($signedOutOthers)->toBe(1)
        ->and(DeviceSession::query()->where('session_id', 'remote-session-2')->exists())->toBeFalse();
});

it('reloads MaxmindIpIntelligence readers cleanly when config paths change under Octane', function (): void {
    $intel = new MaxmindIpIntelligence;

    config()->set('filament-loginguard.ip_intel.enabled', true);
    config()->set('filament-loginguard.ip_intel.databases.country', '/nonexistent/path.mmdb');

    expect($intel->lookup('8.8.8.8'))->toBeNull();

    $intel->flushReaders();
    config()->set('filament-loginguard.ip_intel.enabled', false);

    expect($intel->lookup('8.8.8.8'))->toBeNull();
});
