<?php

use Filament\Facades\Filament;
use Filament\Panel;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Auth\SessionGuard;
use Illuminate\Http\Request;
use Illuminate\Session\DatabaseSessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
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

beforeEach(function () {
    config()->set('session.driver', 'database');
    config()->set('auth.providers.users.model', User::class);
    config()->set('filament-loginguard.devices.notifications.new_device', false);

    session()->setId(str_repeat('c', 40));
});

/** @return array{Device, string} */
function makeDeviceForRevocation(User $user, array $attributes = []): array
{
    $token = DeviceCookie::generateToken();

    $device = Device::query()->create(array_merge([
        'guard' => 'web',
        'user_type' => $user::class,
        'user_identifier' => (string) $user->getAuthIdentifier(),
        'token_hash' => DeviceCookie::hash($token),
        'device_name' => 'Chrome on Windows',
        'first_seen_at' => now()->subDay(),
        'last_seen_at' => now(),
    ], $attributes));

    return [$device, $token];
}

/** Persist an actual authenticated session as well as its device mapping. */
function persistSessionForRevocation(Device $device, string $sessionId): void
{
    DB::table('sessions')->insert([
        'id' => $sessionId,
        'user_id' => $device->user_identifier,
        'payload' => base64_encode(serialize([
            Auth::guard('web')->getName() => $device->user_identifier,
            '_token' => Str::random(40),
        ])),
        'last_activity' => now()->timestamp,
    ]);

    DeviceSession::query()->create([
        'device_id' => $device->id,
        'session_id' => $sessionId,
        'guard' => 'web',
        'last_seen_at' => now(),
    ]);
}

/**
 * Re-read authentication from the database, not a guard's cached user.
 * No remember-me cookie is supplied: this tests session-ID authentication.
 */
function freshGuardForRevocation(string $sessionId): SessionGuard
{
    $store = new Store(
        'loginguard-revocation-test',
        new DatabaseSessionHandler(DB::connection(), 'sessions', 120, app()),
    );
    $store->setId($sessionId);
    $store->start();

    return new SessionGuard(
        'web',
        new EloquentUserProvider(app('hash'), User::class),
        $store,
        Request::create('/'),
    );
}

it('deletes the revoked devices real sessions without deleting unrelated sessions', function () {
    $owner = UserFactory::new()->create();
    $otherUser = UserFactory::new()->create();
    [$target] = makeDeviceForRevocation($owner, ['trusted_at' => now()->subHour()]);
    [$current] = makeDeviceForRevocation($owner);
    [$unrelated] = makeDeviceForRevocation($otherUser);

    $targetIds = [Str::random(40), Str::random(40)];
    foreach ($targetIds as $id) {
        persistSessionForRevocation($target, $id);
    }
    persistSessionForRevocation($current, session()->getId());
    $unrelatedId = Str::random(40);
    persistSessionForRevocation($unrelated, $unrelatedId);

    // A mapping whose session already expired/was deleted must also be cleaned.
    DeviceSession::query()->create([
        'device_id' => $target->id,
        'session_id' => Str::random(40),
        'guard' => 'web',
        'last_seen_at' => now()->subDay(),
    ]);

    app(DeviceManager::class)->revoke($target, reason: 'this_is_not_me');

    expect(DB::table('sessions')->whereIn('id', $targetIds)->count())->toBe(0)
        ->and($target->sessions()->count())->toBe(0)
        ->and(DB::table('sessions')->where('id', session()->getId())->exists())->toBeTrue()
        ->and(DB::table('sessions')->where('id', $unrelatedId)->exists())->toBeTrue()
        ->and($current->sessions()->count())->toBe(1)
        ->and($unrelated->sessions()->count())->toBe(1)
        ->and($target->refresh()->revoked_at)->not->toBeNull()
        ->and($target->trusted_at)->toBeNull();

    $event = SecurityEvent::query()->where('type', SecurityEvent::TYPE_DEVICE_REVOKED)->sole();
    expect($event->metadata['device_id'])->toBe($target->id)
        ->and($event->metadata['reason'])->toBe('this_is_not_me');
});

it('cannot authenticate again using a revoked session id', function () {
    $owner = UserFactory::new()->create();
    [$target] = makeDeviceForRevocation($owner);
    $sessionId = Str::random(40);
    persistSessionForRevocation($target, $sessionId);

    expect(freshGuardForRevocation($sessionId)->id())->toBe($owner->getAuthIdentifier());

    app(DeviceManager::class)->revoke($target);

    // A fresh Store + SessionGuard models the next request with the old ID.
    expect(freshGuardForRevocation($sessionId)->check())->toBeFalse();
});

it('rejects revoking a device mapped to the current session before any deletion', function () {
    $owner = UserFactory::new()->create();
    [$current] = makeDeviceForRevocation($owner, ['trusted_at' => now()->subHour()]);
    persistSessionForRevocation($current, session()->getId());
    $secondSessionId = Str::random(40);
    persistSessionForRevocation($current, $secondSessionId);

    try {
        app(DeviceManager::class)->revoke($current);
        $this->fail('The service must reject revocation of the current session.');
    } catch (HttpException $exception) {
        expect($exception->getStatusCode())->toBe(403);
    }

    expect($current->sessions()->count())->toBe(2)
        ->and(DB::table('sessions')->where('id', session()->getId())->exists())->toBeTrue()
        ->and(DB::table('sessions')->where('id', $secondSessionId)->exists())->toBeTrue()
        ->and($current->refresh()->revoked_at)->toBeNull()
        ->and($current->trusted_at)->not->toBeNull()
        ->and(SecurityEvent::query()->where('type', SecurityEvent::TYPE_DEVICE_REVOKED)->count())->toBe(0);
});

it('rolls back session deletion and mappings when persisting revocation fails', function () {
    $owner = UserFactory::new()->create();
    [$target] = makeDeviceForRevocation($owner);
    $sessionId = Str::random(40);
    persistSessionForRevocation($target, $sessionId);
    $deviceId = $target->getKey();

    Device::saving(function (Device $device) use ($deviceId): void {
        if ($device->getKey() === $deviceId && $device->isDirty('revoked_at')) {
            throw new RuntimeException('Simulated device save failure.');
        }
    });

    expect(fn () => app(DeviceManager::class)->revoke($target))
        ->toThrow(RuntimeException::class, 'Simulated device save failure.');

    expect(DB::table('sessions')->where('id', $sessionId)->exists())->toBeTrue()
        ->and($target->sessions()->where('session_id', $sessionId)->exists())->toBeTrue()
        ->and($target->refresh()->revoked_at)->toBeNull()
        ->and(SecurityEvent::query()->where('type', SecurityEvent::TYPE_DEVICE_REVOKED)->count())->toBe(0);
});

it('can revoke an identity whose sessions no longer exist', function () {
    $owner = UserFactory::new()->create();
    [$target] = makeDeviceForRevocation($owner, ['trusted_at' => now()->subHour()]);

    app(DeviceManager::class)->revoke($target);

    expect($target->refresh()->revoked_at)->not->toBeNull()
        ->and($target->trusted_at)->toBeNull()
        ->and(SecurityEvent::query()->where('type', SecurityEvent::TYPE_DEVICE_REVOKED)->count())->toBe(1);
});

it('does not recognize the actual revoked cookie token on the next login', function () {
    $owner = UserFactory::new()->create();
    [$target, $rawToken] = makeDeviceForRevocation($owner);
    $manager = app(DeviceManager::class);
    $manager->revoke($target);

    // Unlike the previous test, actually send the revoked token back.
    request()->cookies->set(DeviceCookie::name(), $rawToken);
    [$resolved, $isNew] = $manager->resolveOrCreate($owner, 'web', 'Chrome UA', '203.0.113.1');

    expect($isNew)->toBeTrue()
        ->and($resolved->is($target))->toBeFalse()
        ->and($resolved->token_hash)->not->toBe(DeviceCookie::hash($rawToken))
        ->and($target->refresh()->revoked_at)->not->toBeNull();
});

it('terminates the real session through the My Devices this-isnt-me action', function () {
    $panel = Panel::make()->id('admin')->default()->plugin(FilamentLoginGuardPlugin::make());
    Filament::registerPanel($panel);
    Filament::setCurrentPanel($panel);

    $owner = UserFactory::new()->create();
    $this->actingAs($owner);
    [$target] = makeDeviceForRevocation($owner);
    $sessionId = Str::random(40);
    persistSessionForRevocation($target, $sessionId);

    Livewire::test(MyDevices::class)
        ->callAction('revokeDevice', arguments: ['device' => $target->id])
        ->assertHasNoActionErrors();

    expect(DB::table('sessions')->where('id', $sessionId)->exists())->toBeFalse()
        ->and($target->sessions()->count())->toBe(0)
        ->and($target->refresh()->revoked_at)->not->toBeNull();
});

it('does not revoke another users device through a forged action argument', function () {
    $panel = Panel::make()->id('admin')->default()->plugin(FilamentLoginGuardPlugin::make());
    Filament::registerPanel($panel);
    Filament::setCurrentPanel($panel);

    $owner = UserFactory::new()->create();
    $otherUser = UserFactory::new()->create();
    $this->actingAs($owner);
    [$target] = makeDeviceForRevocation($otherUser);
    $sessionId = Str::random(40);
    persistSessionForRevocation($target, $sessionId);

    Livewire::test(MyDevices::class)
        ->callAction('revokeDevice', arguments: ['device' => $target->id]);

    expect(DB::table('sessions')->where('id', $sessionId)->exists())->toBeTrue()
        ->and($target->sessions()->count())->toBe(1)
        ->and($target->refresh()->revoked_at)->toBeNull()
        ->and(SecurityEvent::query()->where('type', SecurityEvent::TYPE_DEVICE_REVOKED)->count())->toBe(0);
});
