<?php

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
        app(DeviceManager::class)->resolveOrCreate($owner, 'web', null, '192.0.2.2');

        return response()->noContent();
    });

    $this->post('/login-interleaved-prune')->assertNoContent();

    expect(Device::query()->sole()->first_ip)->toBe('192.0.2.2')
        ->and(DeviceSession::query()->count())->toBe(0)
        ->and(DB::table('sessions')->where('user_id', $owner->getKey())->exists())->toBeFalse();
});

it('maps each session guard to its own user model when both sign in during the request', function () {
    config()->set('auth.guards.secondary', ['driver' => 'session', 'provider' => 'secondary-users']);
    config()->set('auth.providers.secondary-users', ['driver' => 'eloquent', 'model' => SecondarySessionLifecycleUser::class]);
    $owner = UserFactory::new()->create();
    $secondary = SecondarySessionLifecycleUser::query()->findOrFail($owner->getKey());
    Route::middleware('web')->post('/login-two-guards', function () use ($owner, $secondary) {
        Auth::guard('web')->login($owner);
        Auth::guard('secondary')->login($secondary);

        return response()->noContent();
    });

    $this->post('/login-two-guards')->assertNoContent();

    $sessionId = DB::table('sessions')->where('user_id', $owner->getKey())->sole()->id;
    $mappings = DeviceSession::query()->with('device')->get()->keyBy('guard');

    expect($mappings)->toHaveCount(2)
        ->and($mappings['web']->session_id)->toBe($sessionId)
        ->and($mappings['web']->device->user_type)->toBe(User::class)
        ->and($mappings['secondary']->session_id)->toBe($sessionId)
        ->and($mappings['secondary']->device->user_type)->toBe(SecondarySessionLifecycleUser::class);
});

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
