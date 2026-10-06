<?php

use Carbon\Carbon;
use Filament\Facades\Filament;
use Filament\Panel;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Livewire\Livewire;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;
use SolutionForest\FilamentLoginGuard\Listeners\AuthenticationListener;
use SolutionForest\FilamentLoginGuard\Models\Device;
use SolutionForest\FilamentLoginGuard\Models\DeviceSession;
use SolutionForest\FilamentLoginGuard\Models\KnownDevice;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;
use SolutionForest\FilamentLoginGuard\Pages\MyDevices;
use SolutionForest\FilamentLoginGuard\Services\DeviceManager;
use SolutionForest\FilamentLoginGuard\Support\DeviceCookie;
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

    config()->set('session.driver', 'database');
    config()->set('filament-loginguard.lockout.whitelist.ips', []);
    config()->set('filament-loginguard.devices.notifications.new_device', false);
});

afterEach(function () {
    Carbon::setTestNow(null);
});

/**
 * Seed a device identity for a user and return [Device, rawToken].
 */
function seedDevice(string $guard, string $userType, string $identifier, array $overrides = []): array
{
    $token = DeviceCookie::generateToken();

    $device = Device::query()->create(array_merge([
        'guard' => $guard,
        'user_type' => $userType,
        'user_identifier' => $identifier,
        'token_hash' => DeviceCookie::hash($token),
        'device_name' => 'Chrome on Windows',
        'first_ip' => '1.2.3.4',
        'last_ip' => '1.2.3.4',
        'first_seen_at' => now()->subDays(2),
        'last_seen_at' => now()->subMinutes(5),
    ], $overrides));

    return [$device, $token];
}

function startSession(string $sessionId): void
{
    DB::table('sessions')->insert([
        'id' => $sessionId,
        'user_id' => 1,
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);
}

/** Boot a My Devices Livewire component with a fixed current session id. */
function devicesPage(string $currentSessionId, string $email = 'ken@example.com')
{
    $component = Livewire::withSession(['_' => $currentSessionId])->test(MyDevices::class);

    // Force the request session id for the actions (session()->getId()).
    session()->setId($currentSessionId);

    return $component;
}

it('resolves the same device when the same browser signs in twice', function () {
    $user = UserFactory::new()->create();
    $guard = 'web';

    request()->server->set('REMOTE_ADDR', '1.2.3.4');
    request()->headers->set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0) Chrome/151 Safari/537.36');

    $manager = app(DeviceManager::class);

    // First login: no cookie → new device + queued cookie.
    [$device1, $isNew1] = $manager->resolveOrCreate($user, $guard, 'Chrome UA', '1.2.3.4');
    expect($isNew1)->toBeTrue()
        ->and(Cookie::queued(DeviceCookie::name()))->not->toBeNull('the device token cookie was queued');

    // Simulate the browser storing the cookie and sending it back on the next
    // request. The queued cookie holds the RAW token (encryption happens in
    // the EncryptCookies middleware, which does not run in Livewire::test).
    $rawToken = Cookie::queued(DeviceCookie::name())->getValue();
    request()->cookies->set(DeviceCookie::name(), $rawToken);

    // Second login: the browser cookie is now in the request.
    [$device2, $isNew2] = $manager->resolveOrCreate($user, $guard, 'Chrome UA', '1.2.3.4');

    expect($device2->is($device1))->toBeTrue()
        ->and($isNew2)->toBeFalse()
        ->and(Device::query()->count())->toBe(1);
});

it('treats two identical browser+os setups as two devices', function () {
    $user = UserFactory::new()->create();

    $manager = app(DeviceManager::class);
    request()->server->set('REMOTE_ADDR', '1.2.3.4');

    // Desktop and laptop both report "Chrome on Windows" but carry different cookies.
    [$desktop] = $manager->resolveOrCreate($user, 'web', 'Chrome UA', '1.2.3.4');
    [$laptop] = $manager->resolveOrCreate($user, 'web', 'Chrome UA', '1.2.3.4');

    expect($desktop->is($laptop))->toBeFalse()
        ->and(Device::query()->count())->toBe(2);
});

it('separates device identities per account on the same browser', function () {
    $ken = UserFactory::new()->create();
    $alice = UserFactory::new()->create();

    $manager = app(DeviceManager::class);
    request()->server->set('REMOTE_ADDR', '1.2.3.4');

    [$kenDevice] = $manager->resolveOrCreate($ken, 'web', 'Chrome UA', '1.2.3.4');

    // Same cookie (the browser is shared), different account.
    [$aliceDevice, $aliceIsNew] = $manager->resolveOrCreate($alice, 'web', 'Chrome UA', '1.2.3.4');

    expect($aliceDevice->is($kenDevice))->toBeFalse()
        ->and($aliceIsNew)->toBeTrue()
        ->and($aliceDevice->user_identifier)->toBe((string) $alice->getAuthIdentifier());
});

it('keeps multi-guard accounts separate', function () {
    $user = UserFactory::new()->create();
    $manager = app(DeviceManager::class);
    request()->server->set('REMOTE_ADDR', '1.2.3.4');

    [$webDevice] = $manager->resolveOrCreate($user, 'web', 'UA', '1.2.3.4');
    [$adminDevice] = $manager->resolveOrCreate($user, 'admin', 'UA', '1.2.3.4');

    expect($webDevice->is($adminDevice))->toBeFalse();
});

it('supports uuid-style user identifiers', function () {
    $uuid = strtolower((string) Str::uuid());
    $user = UserFactory::new()->make();
    $manager = app(DeviceManager::class);
    request()->server->set('REMOTE_ADDR', '1.2.3.4');

    [$device] = $manager->resolveOrCreate(
        new class($uuid) extends User
        {
            public function __construct(private string $uuid) {}

            public function getAuthIdentifier(): mixed
            {
                return $this->uuid;
            }
        },
        'web',
        'UA',
        '1.2.3.4',
    );

    expect($device->user_identifier)->toBe($uuid);
});

it('never revokes the current session through sign out device', function () {
    $user = UserFactory::new()->create();
    [$device] = seedDevice('web', $user::class, (string) $user->getAuthIdentifier());

    startSession('current-session');
    startSession('other-session');
    DeviceSession::query()->create(['device_id' => $device->id, 'session_id' => 'current-session', 'guard' => 'web', 'last_seen_at' => now()]);
    DeviceSession::query()->create(['device_id' => $device->id, 'session_id' => 'other-session', 'guard' => 'web', 'last_seen_at' => now()]);

    app(DeviceManager::class)->signOutDevice($device, 'current-session');

    expect(DB::table('sessions')->where('id', 'current-session')->exists())->toBeTrue()
        ->and(DB::table('sessions')->where('id', 'other-session')->exists())->toBeFalse()
        ->and($device->refresh()->revoked_at)->toBeNull('sign out keeps the device recognized');
});

it('revokes the device on this-isnt-me and the token never revives', function () {
    $user = UserFactory::new()->create();
    [$device, $token] = seedDevice('web', $user::class, (string) $user->getAuthIdentifier());

    startSession('stolen-session');
    DeviceSession::query()->create(['device_id' => $device->id, 'session_id' => 'stolen-session', 'guard' => 'web', 'last_seen_at' => now()]);

    app(DeviceManager::class)->revoke($device, reason: 'this_is_not_me');

    expect($device->refresh()->revoked_at)->not->toBeNull()
        ->and($device->sessions()->count())->toBe(0)
        ->and(SecurityEvent::query()->where('type', SecurityEvent::TYPE_DEVICE_REVOKED)->count())->toBe(1);

    // The same cookie coming back must NOT be treated as recognized.
    [$resolved, $isNew] = app(DeviceManager::class)->resolveOrCreate($user, 'web', 'Chrome UA', '1.2.3.4');

    expect($resolved->is($device))->toBeFalse()
        ->and($isNew)->toBeTrue()
        ->and($device->refresh()->revoked_at)->not->toBeNull('revoked stays revoked');
});

it('forgets a device so its next sign-in is a new device', function () {
    $user = UserFactory::new()->create();
    [$device, $token] = seedDevice('web', $user::class, (string) $user->getAuthIdentifier());

    app(DeviceManager::class)->forget($device);

    expect(Device::query()->whereKey($device->id)->exists())->toBeFalse()
        ->and(SecurityEvent::query()->where('type', SecurityEvent::TYPE_DEVICE_FORGOTTEN)->count())->toBe(1);

    [$fresh, $isNew] = app(DeviceManager::class)->resolveOrCreate($user, 'web', 'Chrome UA', '1.2.3.4');

    expect($isNew)->toBeTrue()
        ->and($fresh->is($device))->toBeFalse();
});

it('signs out everywhere else while keeping the current session and devices', function () {
    $user = UserFactory::new()->create();

    [$deviceA] = seedDevice('web', $user::class, (string) $user->getAuthIdentifier());
    [$deviceB] = seedDevice('web', $user::class, (string) $user->getAuthIdentifier(), ['device_name' => 'Safari on iPhone']);

    startSession('current');
    startSession('phone');
    startSession('tablet');
    DeviceSession::query()->create(['device_id' => $deviceA->id, 'session_id' => 'current', 'guard' => 'web', 'last_seen_at' => now()]);
    DeviceSession::query()->create(['device_id' => $deviceA->id, 'session_id' => 'phone', 'guard' => 'web', 'last_seen_at' => now()]);
    DeviceSession::query()->create(['device_id' => $deviceB->id, 'session_id' => 'tablet', 'guard' => 'web', 'last_seen_at' => now()]);

    $deleted = app(DeviceManager::class)->signOutOthers($user, 'web', $user::class, (string) $user->getAuthIdentifier(), 'current');

    expect($deleted)->toBe(2)
        ->and(DB::table('sessions')->where('id', 'current')->exists())->toBeTrue()
        ->and(DB::table('sessions')->whereIn('id', ['phone', 'tablet'])->exists())->toBeFalse()
        // Devices are NOT revoked by "sign out everywhere else".
        ->and($deviceA->refresh()->revoked_at)->toBeNull()
        ->and($deviceB->refresh()->revoked_at)->toBeNull()
        ->and(SecurityEvent::query()->where('type', SecurityEvent::TYPE_SESSIONS_REVOKED_OTHERS)->count())->toBe(1);
});

it('shows only the current users devices on the page', function () {
    $user = UserFactory::new()->create();
    $this->actingAs($user);

    [$device] = seedDevice('web', $user::class, (string) $user->getAuthIdentifier());

    seedDevice('web', User::class, '99999'); // someone else's device

    Livewire::test(MyDevices::class)
        ->assertSuccessful()
        ->assertSee('Chrome on Windows');

    expect(Device::query()->count())->toBe(2);

    // The page's device list is ownership-scoped: actions on someone else's
    // device resolve to null and do nothing.
    $someoneElses = Device::query()->where('user_identifier', '99999')->sole();
    Livewire::test(MyDevices::class)
        ->callAction('forgetDevice', arguments: ['device' => $someoneElses->id]);

    expect($someoneElses->refresh()->exists)->toBeTrue();
});

it('respects the max devices per user cap', function () {
    config()->set('filament-loginguard.devices.max_devices_per_user', 2);

    $user = UserFactory::new()->create();
    $manager = app(DeviceManager::class);
    request()->server->set('REMOTE_ADDR', '1.2.3.4');

    $manager->resolveOrCreate($user, 'web', 'UA', '1.2.3.4');
    $manager->resolveOrCreate($user, 'web', 'UA', '1.2.3.4');
    $manager->resolveOrCreate($user, 'web', 'UA', '1.2.3.4');
    $manager->resolveOrCreate($user, 'web', 'UA', '1.2.3.4');

    expect(Device::query()->count())->toBeLessThanOrEqual(2);
});

it('cleans up dead session mappings and old devices', function () {
    $user = UserFactory::new()->create();
    [$device] = seedDevice('web', $user::class, (string) $user->getAuthIdentifier());

    // Mapping to a dead session.
    DeviceSession::query()->create(['device_id' => $device->id, 'session_id' => 'dead-session', 'guard' => 'web', 'last_seen_at' => now()]);

    // An old device beyond retention.
    $old = Device::query()->create([
        'guard' => 'web',
        'user_type' => $user::class,
        'user_identifier' => (string) $user->getAuthIdentifier(),
        'token_hash' => str_repeat('f', 64),
        'first_seen_at' => now()->subDays(200),
        'last_seen_at' => now()->subDays(200),
    ]);

    app(DeviceManager::class)->cleanup();

    expect($device->sessions()->count())->toBe(0)
        ->and(Device::query()->whereKey($old->id)->exists())->toBeFalse()
        ->and(Device::query()->whereKey($device->id)->exists())->toBeTrue();
});

it('records device events', function () {
    $user = UserFactory::new()->create();
    $manager = app(DeviceManager::class);
    request()->server->set('REMOTE_ADDR', '1.2.3.4');

    $manager->resolveOrCreate($user, 'web', 'UA', '1.2.3.4');

    expect(SecurityEvent::query()->where('type', SecurityEvent::TYPE_DEVICE_REGISTERED)->count())->toBe(1)
        ->and(SecurityEvent::query()->where('type', SecurityEvent::TYPE_DEVICE_SEEN)->count())->toBe(1);
});

it('does not write a device_seen event on every request', function () {
    $user = UserFactory::new()->create();
    $manager = app(DeviceManager::class);
    request()->server->set('REMOTE_ADDR', '1.2.3.4');

    $manager->resolveOrCreate($user, 'web', 'UA', '1.2.3.4');
    $manager->resolveOrCreate($user, 'web', 'UA', '1.2.3.4');

    // resolveOrCreate records "seen" only per login, not per request elsewhere.
    expect(SecurityEvent::query()->where('type', SecurityEvent::TYPE_DEVICE_SEEN)->count())->toBe(2);
});

it('still runs the legacy fingerprint logic alongside device identity', function () {
    config()->set('filament-loginguard.sessions.enabled', true);

    request()->server->set('REMOTE_ADDR', '1.2.3.4');
    request()->headers->set('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36');

    $listener = app(AuthenticationListener::class);
    $user = UserFactory::new()->create();

    $listener->handleLogin(new Login('web', $user, false));

    // Legacy known_devices table still gets its fingerprint row...
    expect(KnownDevice::query()->count())->toBe(1)
        // ...and the new device identity layer got its row too.
        ->and(Device::query()->count())->toBe(1)
        ->and(DeviceSession::query()->count())->toBe(1);
});
