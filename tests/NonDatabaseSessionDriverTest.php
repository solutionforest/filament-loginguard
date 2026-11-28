<?php

use Carbon\Carbon;
use Filament\Facades\Filament;
use Filament\Panel;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\FileSessionHandler;
use Illuminate\Session\Store;
use Livewire\Livewire;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;
use SolutionForest\FilamentLoginGuard\Models\Device;
use SolutionForest\FilamentLoginGuard\Models\DeviceSession;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;
use SolutionForest\FilamentLoginGuard\Pages\MyDevices;
use SolutionForest\FilamentLoginGuard\Services\DeviceManager;
use SolutionForest\FilamentLoginGuard\Support\DeviceCookie;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;

beforeEach(function (): void {
    Carbon::setTestNow('2026-06-01 12:00:00');

    $panel = Panel::make()
        ->id('admin')
        ->default()
        ->plugin(FilamentLoginGuardPlugin::make());

    Filament::registerPanel($panel);
    Filament::setCurrentPanel($panel);

    config()->set('session.lifetime', 120);
    config()->set('filament-loginguard.devices.notifications.new_device', false);
});

afterEach(function (): void {
    Carbon::setTestNow(null);
});

/** Switch the app to a non-database session driver backed by the given handler. */
function useSessionDriver(string $driver, ?SessionHandlerInterface $handler = null): Store
{
    config()->set('session.driver', $driver);

    $store = new Store('laravel_session', $handler ?? new ArraySessionHandler(120));
    app()->instance('session.store', $store);
    request()->setLaravelSession($store);

    return $store;
}

/** @return array{Device, string} [device, raw cookie token] */
function nonDbDevice(User $user, string $name): array
{
    $token = DeviceCookie::generateToken();

    $device = Device::query()->create([
        'guard' => 'web',
        'user_type' => $user::class,
        'user_identifier' => (string) $user->getKey(),
        'token_hash' => DeviceCookie::hash($token),
        'device_name' => $name,
        'first_seen_at' => now()->subDays(3),
        'last_seen_at' => now()->subMinutes(5),
    ]);

    return [$device, $token];
}

function mapSession(Device $device, string $sessionId, Carbon $lastSeenAt): DeviceSession
{
    return DeviceSession::query()->create([
        'device_id' => $device->id,
        'guard' => 'web',
        'session_id' => $sessionId,
        'last_seen_at' => $lastSeenAt,
    ]);
}

it('renders My Devices without a sessions table on the array driver and signs a live device out', function (): void {
    useSessionDriver('array');
    // No sessions table, without DDL (MySQL DDL would implicitly commit the test transaction).
    config()->set('filament-loginguard.sessions.table', 'missing_sessions_table');

    /** @var User $user */
    $user = UserFactory::new()->create();
    $this->actingAs($user);

    [$current, $token] = nonDbDevice($user, 'Firefox on Linux');
    [$other] = nonDbDevice($user, 'Safari on iPhone');
    [$stale] = nonDbDevice($user, 'Edge on Windows');
    mapSession($other, 'live-remote-session', now()->subMinutes(10));
    mapSession($stale, 'expired-remote-session', now()->subMinutes(121));

    request()->cookies->set(DeviceCookie::name(), $token);

    $page = Livewire::test(MyDevices::class)
        ->assertSuccessful()
        ->assertSeeInOrder(['Other signed-in devices', 'Safari on iPhone', 'Sign out', 'Recently signed out', 'Edge on Windows']);

    // The mapped, fresh session is live: forgetting it is refused...
    expect(fn () => app(DeviceManager::class)->forget($other))
        ->toThrow(HttpException::class);

    // ...while the expired mapping is "previous" and can be forgotten.
    $page->callAction('forgetDevice', arguments: ['device' => $stale->id])
        ->assertHasNoActionErrors();
    expect(Device::query()->whereKey($stale->id)->exists())->toBeFalse();

    $page->callAction('signOutDevice', arguments: ['device' => $other->id])
        ->assertHasNoActionErrors()
        ->assertNotified('Device signed out.');

    expect(DeviceSession::query()->where('session_id', 'live-remote-session')->exists())->toBeFalse()
        ->and(SecurityEvent::query()->where('type', SecurityEvent::TYPE_SESSION_REVOKED_BY_USER)->count())->toBe(1)
        ->and(Device::query()->whereKey($current->id)->exists())->toBeTrue();
});

it('hides remote sign-out on the cookie session driver and never reports a fake success', function (): void {
    useSessionDriver('cookie');

    /** @var User $user */
    $user = UserFactory::new()->create();
    $this->actingAs($user);

    [, $token] = nonDbDevice($user, 'Firefox on Linux');
    [$other] = nonDbDevice($user, 'Safari on iPhone');
    mapSession($other, 'cookie-remote-session', now()->subMinutes(10));

    request()->cookies->set(DeviceCookie::name(), $token);

    Livewire::test(MyDevices::class)
        ->assertSuccessful()
        ->assertSee('Safari on iPhone')
        ->assertSee('sessions are stored in browser cookies')
        ->assertDontSee('mountAction(\'signOutDevice\'', escape: false)
        ->assertActionHidden('signOutOthers')
        ->assertActionHidden('signOutDevice');

    $manager = app(DeviceManager::class);

    expect($manager->signOutDevice($other, 'current-session'))->toBe(0)
        ->and($manager->signOutOthers($user, 'web', $user::class, (string) $user->getKey(), 'current-session'))->toBe(0)
        ->and(SecurityEvent::query()->where('type', SecurityEvent::TYPE_SESSIONS_REVOKED_OTHERS)->exists())->toBeFalse()
        ->and(DeviceSession::query()->where('session_id', 'cookie-remote-session')->exists())->toBeTrue();
});

it('counts only fresh mapped sessions as signed out on the file driver', function (): void {
    $directory = sys_get_temp_dir() . '/flg-sessions-' . bin2hex(random_bytes(4));
    mkdir($directory);
    useSessionDriver('file', new FileSessionHandler(new Filesystem, $directory, 120));
    file_put_contents($directory . '/fresh-file-session', 'payload');

    /** @var User $user */
    $user = UserFactory::new()->create();
    [$device] = nonDbDevice($user, 'Safari on iPhone');
    mapSession($device, 'fresh-file-session', now()->subMinutes(5));
    mapSession($device, 'expired-file-session', now()->subMinutes(500));

    // FileSessionHandler::destroy() returns true for any id; the expired
    // mapping must not inflate the result.
    expect(app(DeviceManager::class)->signOutDevice($device, 'current-session'))->toBe(1)
        ->and(file_exists($directory . '/fresh-file-session'))->toBeFalse()
        ->and($device->sessions()->count())->toBe(0);

    (new Filesystem)->deleteDirectory($directory);
});

it('prunes mappings older than the session lifetime on non-database drivers', function (): void {
    useSessionDriver('redis', new ArraySessionHandler(120));

    /** @var User $user */
    $user = UserFactory::new()->create();
    [$device] = nonDbDevice($user, 'Safari on iPhone');
    mapSession($device, 'fresh', now()->subMinutes(30));
    mapSession($device, 'stale', now()->subMinutes(121));

    app(DeviceManager::class)->cleanup();

    expect($device->sessions()->pluck('session_id')->all())->toBe(['fresh']);

    // Session rotation prunes the device's stale mappings too.
    mapSession($device, 'rotated-away', now()->subMinutes(200));

    expect(app(DeviceManager::class)->associatePersistedSession([$device], 'new-session', 'rotated-away'))->toBeTrue()
        ->and($device->sessions()->orderBy('session_id')->pluck('session_id')->all())->toBe(['fresh', 'new-session']);
});

it('keeps an in-use session live on non-database drivers with a throttled heartbeat', function (): void {
    $store = useSessionDriver('redis', new ArraySessionHandler(120));
    $store->setId(str_repeat('a', 40));
    $store->start();

    /** @var User $user */
    $user = UserFactory::new()->create();
    [$device] = nonDbDevice($user, 'Safari on iPhone');
    $mapping = mapSession($device, $store->getId(), now()->subMinutes(119));

    event(new Authenticated('web', $user));

    expect($mapping->refresh()->last_seen_at->equalTo(now()))->toBeTrue();

    // Within the throttle window no further write happens.
    $mapping->forceFill(['last_seen_at' => now()->subMinutes(10)])->save();
    Carbon::setTestNow(now()->addSeconds(30));
    event(new Authenticated('web', $user));

    expect($mapping->refresh()->last_seen_at->diffInMinutes(now(), true))->toBeGreaterThan(9);

    Carbon::setTestNow(now()->addSeconds(31));
    event(new Authenticated('web', $user));

    expect($mapping->refresh()->last_seen_at->equalTo(now()))->toBeTrue()
        ->and($device->hasActiveSessions())->toBeTrue();
});
