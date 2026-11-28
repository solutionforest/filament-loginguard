<?php

namespace SolutionForest\FilamentLoginGuard\Listeners;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\SessionGuard;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Http\Events\RequestHandled;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use SolutionForest\FilamentLoginGuard\Events\LoginLockedOut;
use SolutionForest\FilamentLoginGuard\LoginGuardService;
use SolutionForest\FilamentLoginGuard\Models\Device;
use SolutionForest\FilamentLoginGuard\Models\LocationHistory;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;
use SolutionForest\FilamentLoginGuard\Services\DeviceManager;
use SolutionForest\FilamentLoginGuard\Services\IpIntelligence;
use SolutionForest\FilamentLoginGuard\Support\IpAddress;
use SolutionForest\FilamentLoginGuard\Support\ParsesUserAgent;
use SolutionForest\FilamentLoginGuard\Support\SessionDriver;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;

class AuthenticationListener
{
    private const LOGIN_REQUEST = 'filament-loginguard.login-request';

    private const SESSION_BINDINGS = 'filament-loginguard.device-bindings';

    private const PREVIOUS_SESSION = 'filament-loginguard.previous-session';

    private const MAPPINGS_TOUCHED_AT = 'filament-loginguard.mappings-touched-at';

    /** Minimum seconds between two heartbeats of the same session's mappings. */
    private const HEARTBEAT_SECONDS = 60;

    public function __construct(
        protected LoginGuardService $service,
        protected DeviceManager $deviceManager,
        protected IpIntelligence $ipIntelligence,
    ) {}

    /**
     * Pre-check: throw before any credential work so locked keys are rejected fast
     * (Filament runs this inside a Timebox, so the padding still applies).
     */
    public function handleAttempting(Attempting $event): void
    {
        if (! $this->service->isEnabled() || ! $this->shouldTrackGuard($event->guard)) {
            return;
        }

        $ip = IpAddress::fromRequest();
        $email = $this->emailFromCredentials($event->credentials);

        if ($this->service->isWhitelisted($ip, $email)) {
            return;
        }

        if (! $this->service->isLocked($ip, $email)) {
            return;
        }

        throw $this->lockoutException($this->service->remainingLockSeconds($ip, $email));
    }

    /**
     * Record a failure; when this attempt triggers a lockout, notify and surface the lockout message.
     */
    public function handleFailed(Failed $event): void
    {
        if (! $this->service->isEnabled() || ! $this->shouldTrackGuard($event->guard)) {
            return;
        }

        $email = $this->emailFromCredentials($event->credentials);

        if ($email === null) {
            return; // nothing to key on
        }

        $ip = IpAddress::fromRequest();

        if ($this->service->isWhitelisted($ip, $email) || $this->service->isLocked($ip, $email)) {
            return; // never count/extend during an active lock
        }

        SecurityEvent::record(
            SecurityEvent::TYPE_LOGIN_FAILED,
            $ip,
            $email,
            null,
            $event->guard,
            ParsesUserAgent::parseDeviceName(request()->userAgent()),
            $this->ipIntelligence->lookup($ip)?->toArray(),
        );

        $result = $this->service->recordFailure($ip, $email, request()->userAgent());

        if (! $result->locked) {
            return;
        }

        // Extension hook: apps can listen for Slack/webhook alerting etc.
        LoginLockedOut::dispatch($ip, $email, $result->minutes);

        $this->service->notifyLockout($ip, $email, $result->minutes);

        throw $this->lockoutException($result->secondsRemaining);
    }

    /**
     * Successful login: record the success on the (ip, email) row, remember the
     * device fingerprint, and enforce the per-user concurrent session limit.
     */
    public function handleLogin(Login $event): void
    {
        // Session security features (new-device tracking, concurrent limit) are
        // gated by `sessions.enabled`, NOT by the admin page toggle — hiding the
        // page must not silently disable the security behavior.
        $guardTracked = $this->service->isEnabled() && $this->shouldTrackGuard($event->guard);
        $sessionsEnabled = (bool) config('filament-loginguard.sessions.enabled', true);

        if (! $guardTracked && ! $sessionsEnabled && ! (bool) config('filament-loginguard.devices.enabled', true)) {
            return;
        }

        $ip = IpAddress::fromRequest();

        $email = null;

        if (method_exists($event->user, 'getAttribute')) {
            $value = $event->user->getAttribute('email');

            if (is_string($value) && filled($value)) {
                $email = Str::lower(trim($value));
            }
        }

        $userId = $event->user->getAuthIdentifier();
        $userIdInt = is_numeric($userId) && (int) $userId > 0 ? (int) $userId : null;

        $location = $this->ipIntelligence->lookup($ip);

        if ($location !== null) {
            $userType = $event->user::class;
            $identifier = filament_loginguard_identifier($userId);
            $metadata = $location->toArray();

            if ($location->country !== null) {
                $metadata['is_new_country'] = LocationHistory::isNewCountry($event->guard, $userType, $identifier, $location->country);
            }

            if ($location->asn !== null) {
                $metadata['is_new_asn'] = LocationHistory::isNewAsn($event->guard, $userType, $identifier, $location->asn);
            }

            LocationHistory::record($event->guard, $userType, $identifier, $location->country, $location->asn);
        } else {
            $metadata = null;
        }

        if ($guardTracked) {
            if ($email !== null) {
                $this->service->recordSuccess($ip, $email);
            } else {
                $this->service->resetForSuccess($ip, null);
            }
        }

        SecurityEvent::record(
            SecurityEvent::TYPE_LOGIN_SUCCEEDED,
            $ip,
            $email,
            $userIdInt,
            $event->guard,
            ParsesUserAgent::parseDeviceName(request()->userAgent()),
            $metadata,
        );

        $trackDevice = (bool) config('filament-loginguard.devices.enabled', true) && $userId !== null;
        $notifyByIdentity = $trackDevice && (bool) config('filament-loginguard.devices.notifications.new_device', false);

        if ($sessionsEnabled && $userIdInt !== null) {
            $this->service->recordDevice($userIdInt, request()->userAgent(), $notifyByIdentity ? null : $email);
            $this->service->enforceConcurrentLimit($userIdInt);
        }

        // Device identity layer (My Devices): resolve-or-create the device from
        // the opaque cookie token, then map this session onto it. Gated by
        // `devices.enabled`; non-numeric identifiers (UUID/ULID users) still
        // get device tracking via the string identifier column.
        if ($trackDevice) {
            [$device, $isNew] = $this->deviceManager->resolveOrCreate(
                $event->user,
                $event->guard,
                request()->userAgent(),
                $ip,
            );

            // StartSession persists the final ID after Fortify or Filament
            // finishes regenerating the session during the login request.
            if (request()->hasSession()) {
                $this->bindSessionDevice($device);
            } else {
                $sessionId = filament_loginguard_session_id();

                if (filled($sessionId)) {
                    $this->deviceManager->associateSession($device, $event->guard, $sessionId);
                }
            }

            if ($notifyByIdentity && $isNew) {
                try {
                    $this->deviceManager->notifyNewDevice($device, $email);
                } catch (TransportExceptionInterface $exception) {
                    report($exception);
                }
            }
        }
    }

    private function bindSessionDevice(Device $device): void
    {
        $request = request();
        $session = $request->session();
        $stored = $session->get(self::SESSION_BINDINGS);
        $bindings = is_array($stored) ? $stored : [];

        if (! $request->attributes->has(self::LOGIN_REQUEST)) {
            $previousId = $request->cookie($session->getName());
            if (is_string($previousId) && $previousId !== '') {
                $request->attributes->set(self::PREVIOUS_SESSION, $previousId);
                // Upgrade existing sessions from their persisted mappings once.
                if (! is_array($stored)) {
                    $prior = Device::query()->whereHas('sessions', fn (Builder $query) => $query
                        ->where('session_id', $previousId)
                        ->whereColumn('filament_loginguard_device_sessions.guard', 'filament_loginguard_devices.guard'))->get();
                    foreach ($prior as $sibling) {
                        $bindings[$sibling->guard] = $this->deviceManager->sessionBinding($sibling);
                    }
                }
            }
            $request->attributes->set(self::LOGIN_REQUEST, true);
        }

        // This snapshot survives a concurrent revoke deleting the original
        // mapping after StartSession loaded this request's authenticated guards.
        $bindings[$device->guard] = $this->deviceManager->sessionBinding($device);
        $session->put(self::SESSION_BINDINGS, $bindings);
    }

    /**
     * Non-database session stores cannot be queried, so a mapping's
     * `last_seen_at` is its liveness signal. Refresh it (at most once a minute,
     * throttled through the session itself) while the session is in use, so an
     * active session is never treated as expired and pruned.
     */
    public function handleAuthenticated(Authenticated $event): void
    {
        if (SessionDriver::usesDatabase() || ! (bool) config('filament-loginguard.devices.enabled', true)) {
            return;
        }

        $request = request();
        if (! $request->hasSession()) {
            return;
        }

        $session = $request->session();
        $now = Carbon::now()->getTimestamp();
        $touchedAt = $session->get(self::MAPPINGS_TOUCHED_AT);

        if (is_int($touchedAt) && $touchedAt <= $now && $now - $touchedAt < self::HEARTBEAT_SECONDS) {
            return;
        }

        $session->put(self::MAPPINGS_TOUCHED_AT, $now);
        $this->deviceManager->touchSession($session->getId());
    }

    public function handleRequestHandled(RequestHandled $event): void
    {
        $request = $event->request;
        if (! $request->attributes->has(self::LOGIN_REQUEST)) {
            return;
        }

        $session = $request->session();
        $bindings = $session->get(self::SESSION_BINDINGS);
        $bindings = is_array($bindings) ? $bindings : [];
        $active = [];
        foreach ((array) config('auth.guards', []) as $guard => $settings) {
            if (! is_string($guard) || ! is_array($settings)) {
                continue;
            }

            // A pre-upgrade session can retain a guard marker after a revoke
            // removed its only mapping. Require a verifiable binding even then.
            $binding = $bindings[$guard] ?? null;
            if ($binding === null && ($settings['driver'] ?? null) !== 'session') {
                continue;
            }

            $auth = Auth::guard($guard);
            if (! $auth instanceof SessionGuard) {
                continue;
            }

            $identifier = filament_loginguard_identifier($session->get($auth->getName()));
            if ($identifier === '') {
                continue;
            }

            // Use the cached user or provider directly. Invoking user() here
            // could trigger a remember-me login after middleware saved the session.
            $user = $auth->getUser() ?? $auth->getProvider()->retrieveById($identifier);
            if (! is_array($binding) || ! is_int($binding['id'] ?? null) || ($binding['guard'] ?? null) !== $guard
                || ($binding['user_identifier'] ?? null) !== $identifier || $user === null
                || ($binding['user_type'] ?? null) !== $user::class || filament_loginguard_identifier($user->getAuthIdentifier()) !== $identifier) {
                $session->getHandler()->destroy($session->getId());

                return;
            }
            $active[] = ['id' => $binding['id'], 'guard' => $guard, 'user_type' => $user::class, 'user_identifier' => $identifier];
        }

        $previousId = $request->attributes->get(self::PREVIOUS_SESSION);

        try {
            $mapped = $this->deviceManager->associatePersistedSession($active, $session->getId(), is_string($previousId) ? $previousId : null);
        } catch (UniqueConstraintViolationException $exception) {
            // A conflicting token owner must never be replaced by a rekey.
            report($exception);
            $mapped = false;
        }

        if (! $mapped) {
            $session->getHandler()->destroy($session->getId());
        }
    }

    /**
     * @param  array<mixed, mixed>  $credentials
     */
    private function emailFromCredentials(array $credentials): ?string
    {
        $email = $credentials['email'] ?? null;

        return is_string($email) && filled($email) ? Str::lower(trim($email)) : null;
    }

    private function shouldTrackGuard(string $guard): bool
    {
        $guards = (array) config('filament-loginguard.lockout.tracking.guards', []);

        return $guards === [] || in_array($guard, $guards, true);
    }

    private function lockoutException(int $secondsRemaining): ValidationException
    {
        $minutes = max(1, (int) ceil($secondsRemaining / 60));
        $message = filament_loginguard_trans('filament-loginguard::loginguard.messages.locked', ['minutes' => $minutes]);

        // 'data.email' renders inline in the Filament login form (statePath 'data', same key the
        // core Login page uses); plain 'email' covers non-Filament custom login forms that read
        // standard Laravel validation errors. The extra key is inert in Livewire if unmatched.
        return ValidationException::withMessages([
            'data.email' => $message,
            'email' => $message,
        ]);
    }
}
