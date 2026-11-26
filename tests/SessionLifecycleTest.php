<?php

use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Route;
use SolutionForest\FilamentLoginGuard\Models\Device;
use SolutionForest\FilamentLoginGuard\Models\DeviceSession;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;
use SolutionForest\FilamentLoginGuard\Services\DeviceManager;
use SolutionForest\FilamentLoginGuard\Support\DeviceCookie;
use Symfony\Component\Mailer\Exception\TransportException;
use Symfony\Component\Mailer\SentMessage;
use Symfony\Component\Mailer\Transport\AbstractTransport;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;

class SecondarySessionLifecycleUser extends User
{
    protected $table = 'users';
}

/** Persist a pre-upgrade mapping alongside a session with no device binding snapshot. */
function loginFirstLifecycleGuard(User $owner, bool $legacy): void
{
    config()->set('filament-loginguard.devices.enabled', ! $legacy);
    Auth::guard('web')->login($owner);
    if ($legacy) {
        $devices = app(DeviceManager::class);
        [$device] = $devices->resolveOrCreate($owner, 'web', null, '192.0.2.1');
        $devices->associateSession($device, 'web', request()->session()->getId());
        config()->set('filament-loginguard.devices.enabled', true);
    }
}

beforeEach(function () {
    config()->set('session.driver', 'database');
    config()->set('auth.providers.users.model', User::class);
});

it('maps the session persisted after the Fortify login pipeline finishes', function () {
    $owner = UserFactory::new()->create(['password' => Hash::make('local-test-password')]);

    $this->post('/login', ['email' => $owner->email, 'password' => 'local-test-password'])
        ->assertRedirect('/dashboard');

    $persisted = DB::table('sessions')->where('user_id', $owner->getKey())->sole();
    $mapping = DeviceSession::query()->sole();

    expect($mapping->session_id)->toBe($persisted->id)
        ->and($mapping->device->user_identifier)->toBe((string) $owner->getKey())
        ->and($mapping->guard)->toBe('web');

    Route::middleware('web')->get('/session-health', fn () => response()->noContent());
    $this->get('/session-health')->assertNoContent();
    expect(DeviceSession::query()->count())->toBe(1)
        ->and(SecurityEvent::query()->where('type', SecurityEvent::TYPE_DEVICE_SEEN)->count())->toBe(1);
});

it('only maps a device if the account is still signed in when the response finishes', function () {
    $owner = UserFactory::new()->create();
    Route::middleware('web')->post('/complete-logout', function () use ($owner) {
        Auth::guard('web')->login($owner);
        Auth::guard('web')->logout();

        return response()->noContent();
    });

    $this->post('/complete-logout')->assertNoContent();

    expect(SecurityEvent::query()->where('type', SecurityEvent::TYPE_LOGIN_SUCCEEDED)->count())->toBe(1)
        ->and(DeviceSession::query()->count())->toBe(0);
});

it('invalidates the new session if its pending device is revoked before the response', function () {
    $owner = UserFactory::new()->create();
    Route::middleware('web')->post('/login-interleaved-revoke', function () use ($owner) {
        $devices = app(DeviceManager::class);
        [$device] = $devices->resolveOrCreate($owner, 'web', null, '192.0.2.1');
        request()->cookies->set(DeviceCookie::name(), Cookie::queued(DeviceCookie::name())->getValue());

        Auth::guard('web')->login($owner);
        $devices->revoke($device);

        return response()->noContent();
    });

    $this->post('/login-interleaved-revoke')->assertNoContent();

    expect(Device::query()->sole()->isRevoked())->toBeTrue()
        ->and(DeviceSession::query()->count())->toBe(0)
        ->and(DB::table('sessions')->where('user_id', $owner->getKey())->exists())->toBeFalse();
});

it('invalidates the new session if cap pruning removed its pending device', function () {
    config()->set('filament-loginguard.devices.max_devices_per_user', 1);
    $owner = UserFactory::new()->create();
    Route::middleware('web')->post('/login-interleaved-prune', function () use ($owner) {
        Auth::guard('web')->login($owner);

        // Another browser resolves a device while this login awaits session persistence.
        request()->cookies->set(DeviceCookie::name(), DeviceCookie::generateToken());
        app(DeviceManager::class)->resolveOrCreate($owner, 'web', null, '192.0.2.2');

        return response()->noContent();
    });

    $this->post('/login-interleaved-prune')->assertNoContent();

    expect(Device::query()->sole()->first_ip)->toBe('192.0.2.2')
        ->and(DeviceSession::query()->count())->toBe(0)
        ->and(DB::table('sessions')->where('user_id', $owner->getKey())->exists())->toBeFalse();
});

it('maps each guard and user model to the issued cookie when both sign in during the request', function (?string $revokedGuard) {
    config()->set('auth.guards.secondary', ['driver' => 'session', 'provider' => 'secondary-users']);
    config()->set('auth.providers.secondary-users', ['driver' => 'eloquent', 'model' => SecondarySessionLifecycleUser::class]);
    $owner = UserFactory::new()->create();
    $secondary = SecondarySessionLifecycleUser::query()->findOrFail($owner->getKey());
    Route::middleware('web')->post('/login-two-guards', function () use ($owner, $secondary) {
        Auth::guard('web')->login($owner);
        Auth::guard('secondary')->login($secondary);

        return response()->noContent();
    });

    if ($revokedGuard !== null) {
        $manager = app(DeviceManager::class);
        [$webDevice] = $manager->resolveOrCreate($owner, 'web', null, '192.0.2.1');
        [$secondaryDevice] = $manager->resolveOrCreate($secondary, 'secondary', null, '192.0.2.1');
        $this->withCookie(DeviceCookie::name(), Cookie::queued(DeviceCookie::name())->getValue());
        $previous = $revokedGuard === 'web' ? $webDevice : $secondaryDevice;
        $survivor = $revokedGuard === 'web' ? $secondaryDevice : $webDevice;
        $manager->revoke($previous);
    }

    $response = $this->post('/login-two-guards')->assertNoContent();
    $browserHash = DeviceCookie::hash($response->getCookie(DeviceCookie::name())->getValue());

    $sessionId = DB::table('sessions')->where('user_id', $owner->getKey())->sole()->id;
    $mappings = DeviceSession::query()->with('device')->get()->keyBy('guard');

    expect($mappings)->toHaveCount(2)
        ->and($mappings['web']->session_id)->toBe($sessionId)
        ->and($mappings['web']->device->user_type)->toBe(User::class)
        ->and($mappings['secondary']->session_id)->toBe($sessionId)
        ->and($mappings['secondary']->device->user_type)->toBe(SecondarySessionLifecycleUser::class)
        ->and($mappings['web']->device->token_hash)->toBe($browserHash)
        ->and($mappings['secondary']->device->token_hash)->toBe($browserHash);
    if ($revokedGuard !== null) {
        expect($previous->refresh()->isRevoked())->toBeTrue()
            ->and($previous->token_hash)->not->toBe($browserHash)
            ->and($mappings[$survivor->guard]->device_id)->toBe($survivor->id)
            ->and($survivor->refresh()->token_hash)->toBe($browserHash);
    }
})->with([[null], ['web'], ['secondary']]);

it('does not associate the original user if the guard has switched to another model with the same identifier', function () {
    $owner = UserFactory::new()->create();
    $replacement = SecondarySessionLifecycleUser::query()->findOrFail($owner->getKey());
    Route::middleware('web')->post('/login-replaced-model', function () use ($owner, $replacement) {
        Auth::guard('web')->login($owner);
        Auth::guard('web')->setUser($replacement);

        return response()->noContent();
    });

    $this->post('/login-replaced-model')->assertNoContent();

    expect(DeviceSession::query()->count())->toBe(0);
});

it('reports a new-device mail transport failure and still persists the login and mapping', function () {
    config()->set('filament-loginguard.devices.notifications.new_device', true);
    config()->set('mail.default', 'array');
    Mail::mailer('array')->setSymfonyTransport(new class extends AbstractTransport
    {
        protected function doSend(SentMessage $message): void
        {
            throw new TransportException('Device mail transport unavailable');
        }

        public function __toString(): string
        {
            return 'unavailable';
        }
    });
    Exceptions::fake();
    $owner = UserFactory::new()->create(['password' => Hash::make('local-test-password')]);

    $this->post('/login', ['email' => $owner->email, 'password' => 'local-test-password'])->assertRedirect('/dashboard');

    $persisted = DB::table('sessions')->where('user_id', $owner->getKey())->sole();
    expect(DeviceSession::query()->sole()->session_id)->toBe($persisted->id);
    Exceptions::assertReported(fn (TransportException $error): bool => $error->getMessage() === 'Device mail transport unavailable');
});

it('carries an existing authenticated guard mapping onto the session persisted by a later guard login', function (bool $keepFirstGuard, bool $legacy) {
    config()->set('auth.guards.secondary', ['driver' => 'session', 'provider' => 'secondary-users']);
    config()->set('auth.providers.secondary-users', ['driver' => 'eloquent', 'model' => SecondarySessionLifecycleUser::class]);
    $owner = UserFactory::new()->create();
    $other = UserFactory::new()->create();
    $secondary = SecondarySessionLifecycleUser::query()->findOrFail($other->getKey());
    Route::middleware('web')->post('/login-first-guard', function () use ($owner, $legacy) {
        loginFirstLifecycleGuard($owner, $legacy);

        return response()->noContent();
    });
    Route::middleware('web')->post('/login-later-guard', function () use ($owner, $secondary, $keepFirstGuard) {
        abort_unless(Auth::guard('web')->id() === $owner->getKey(), 401);
        if (! $keepFirstGuard) {
            Auth::guard('web')->logout();
        }
        Auth::guard('secondary')->login($secondary);

        return response()->noContent();
    });

    $first = $this->post('/login-first-guard')->assertNoContent();
    $oldId = $first->getCookie(config('session.cookie'))->getValue();
    $firstDevice = DeviceSession::query()->where('session_id', $oldId)->sole()->device_id;
    Auth::forgetGuards();
    app('session')->forgetDrivers();
    app()->forgetInstance('session.store');

    $second = $this->withUnencryptedCookies([
        config('session.cookie') => $first->getCookie(config('session.cookie'), decrypt: false)->getValue(),
        DeviceCookie::name() => $first->getCookie(DeviceCookie::name(), decrypt: false)->getValue(),
    ])
        ->post('/login-later-guard')->assertNoContent();
    $finalId = $second->getCookie(config('session.cookie'))->getValue();
    $mappings = DeviceSession::query()->with('device')->get()->keyBy('guard');

    expect($finalId)->not->toBe($oldId)
        ->and(DB::table('sessions')->where('id', $finalId)->exists())->toBeTrue()
        ->and(DB::table('sessions')->where('id', $oldId)->exists())->toBeFalse()
        ->and($mappings['secondary']->session_id)->toBe($finalId)
        ->and($mappings['secondary']->device->user_identifier)->toBe((string) $other->getKey());
    if ($keepFirstGuard) {
        expect($mappings['web']->device_id)->toBe($firstDevice)
            ->and($mappings['web']->session_id)->toBe($finalId);

        // A separate, authenticated browser revokes the initially mapped device.
        Route::middleware('web')->post('/revoke-first-device', function () use ($owner, $firstDevice) {
            Auth::guard('web')->login($owner);
            app(DeviceManager::class)->revoke(Device::query()->findOrFail($firstDevice));

            return response()->noContent();
        });
        Auth::forgetGuards();
        app('session')->forgetDrivers();
        app()->forgetInstance('session.store');
        $this->call('POST', '/revoke-first-device', cookies: [])->assertNoContent();
        expect(DB::table('sessions')->where('id', $finalId)->exists())->toBeFalse()
            ->and(DeviceSession::query()->where('session_id', $finalId)->exists())->toBeFalse();
    } else {
        expect($mappings->has('web'))->toBeFalse();
    }
})->with([[true, false], [false, false], [true, true]]);

it('discards a regenerated session when a previously loaded sibling binding is revoked', function (bool $legacy) {
    config()->set('auth.guards.secondary', ['driver' => 'session', 'provider' => 'secondary-users']);
    config()->set('auth.providers.secondary-users', ['driver' => 'eloquent', 'model' => SecondarySessionLifecycleUser::class]);
    $owner = UserFactory::new()->create();
    $secondary = SecondarySessionLifecycleUser::query()->findOrFail($owner->getKey());
    Route::middleware('web')->post('/initial-binding', function () use ($owner, $legacy) {
        loginFirstLifecycleGuard($owner, $legacy);

        return response()->noContent();
    });
    $initial = $this->post('/initial-binding')->assertNoContent();
    $firstDevice = DeviceSession::query()->sole()->device;
    Route::middleware('web')->post('/interleaved-sibling-login', function () use ($owner, $secondary, $firstDevice) {
        abort_unless(Auth::guard('web')->id() === $owner->getKey(), 401);
        // This request has loaded the existing guard. An independent device
        // revocation acts before the next guard's Login listener can read mappings.
        $requestStore = app('session.store');
        $operatorStore = clone $requestStore;
        $operatorStore->setId(str_repeat('o', 40));
        app()->instance('session.store', $operatorStore);

        try {
            app(DeviceManager::class)->revoke($firstDevice);
        } finally {
            app()->instance('session.store', $requestStore);
        }
        Auth::guard('secondary')->login($secondary);

        return response()->noContent();
    });
    Auth::forgetGuards();
    app('session')->forgetDrivers();
    app()->forgetInstance('session.store');
    $response = $this->withUnencryptedCookies([
        config('session.cookie') => $initial->getCookie(config('session.cookie'), decrypt: false)->getValue(),
        DeviceCookie::name() => $initial->getCookie(DeviceCookie::name(), decrypt: false)->getValue(),
    ])->post('/interleaved-sibling-login')->assertNoContent();

    $finalId = $response->getCookie(config('session.cookie'))->getValue();
    expect($firstDevice->refresh()->isRevoked())->toBeTrue()
        ->and(DB::table('sessions')->where('id', $finalId)->exists())->toBeFalse()
        ->and(DeviceSession::query()->where('session_id', $finalId)->exists())->toBeFalse();
})->with([false, true]);

it('keeps both existing identities intact when rekeying a sibling would collide', function () {
    config()->set('auth.guards.secondary', ['driver' => 'session', 'provider' => 'secondary-users']);
    config()->set('auth.providers.secondary-users', ['driver' => 'eloquent', 'model' => SecondarySessionLifecycleUser::class]);
    Exceptions::fake();
    $owner = UserFactory::new()->create();
    $secondary = SecondarySessionLifecycleUser::query()->findOrFail($owner->getKey());
    $manager = app(DeviceManager::class);
    [$original] = $manager->resolveOrCreate($owner, 'web', null, '192.0.2.1');
    [$revoked] = $manager->resolveOrCreate($secondary, 'secondary', null, '192.0.2.1');
    $token = DeviceCookie::get();
    $manager->revoke($revoked);

    Route::middleware('web')->post('/rotate-with-collision', function () use ($owner, $secondary, $original) {
        Auth::guard('web')->login($owner);
        Auth::guard('secondary')->login($secondary);
        // Make an existing, unrelated row own the generated target hash.
        $occupied = $original->replicate();
        $occupied->token_hash = DeviceCookie::hash(DeviceCookie::get());
        $occupied->save();

        return response()->noContent();
    });
    $response = $this->withCookie(DeviceCookie::name(), $token)->post('/rotate-with-collision')->assertNoContent();
    $finalId = $response->getCookie(config('session.cookie'))->getValue();
    $newHash = DeviceCookie::hash($response->getCookie(DeviceCookie::name())->getValue());
    expect($original->refresh()->token_hash)->toBe(DeviceCookie::hash($token))
        ->and(Device::query()->where('guard', 'web')->where('token_hash', $newHash)->sole()->id)->not->toBe($original->id)
        ->and(DeviceSession::query()->where('session_id', $finalId)->exists())->toBeFalse()
        ->and(DB::table('sessions')->where('id', $finalId)->exists())->toBeFalse();
    Exceptions::assertReported(UniqueConstraintViolationException::class);
});
