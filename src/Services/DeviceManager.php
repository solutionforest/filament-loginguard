<?php

namespace SolutionForest\FilamentLoginGuard\Services;

use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use SolutionForest\FilamentLoginGuard\Models\Device;
use SolutionForest\FilamentLoginGuard\Models\DeviceSession;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;
use SolutionForest\FilamentLoginGuard\Notifications\NewDeviceLoginNotification;
use SolutionForest\FilamentLoginGuard\Support\DeviceCookie;
use SolutionForest\FilamentLoginGuard\Support\ParsesUserAgent;

/**
 * Owns the device identity layer: resolving or creating the device behind a
 * login, mapping it to sessions, and the device lifecycle actions that the
 * My Devices page exposes. Deliberately separate from LoginGuardService so
 * the brute-force and device-identity concerns stay independent.
 */
class DeviceManager
{
    /**
     * Resolve the device behind the current request for the given account —
     * creating a new identity (and queuing the token cookie) when the cookie
     * is absent, unknown, or bound to a revoked device.
     *
     * Returns the device plus whether this login is the FIRST time this exact
     * device identity was seen for the account.
     *
     * @param  Authenticatable  $user  the authenticated user
     * @return array{0: Device, 1: bool}
     */
    public function resolveOrCreate(Authenticatable $user, string $guard, ?string $userAgent, ?string $ip): array
    {
        $userType = $user::class;
        $identifier = filament_loginguard_identifier($user->getAuthIdentifier());
        $now = Carbon::now();
        $deviceName = ParsesUserAgent::parseDeviceName($userAgent);

        $rawToken = DeviceCookie::get();
        $knownDevice = $rawToken !== null
            ? $this->findByHash($guard, $userType, $identifier, DeviceCookie::hash($rawToken))
            : null;

        // A revoked token must never silently become recognized again; the
        // browser gets a fresh identity on the next login.
        if ($knownDevice !== null && $knownDevice->isRevoked()) {
            $rawToken = DeviceCookie::replaceRevokedToken($knownDevice->token_hash);
            $knownDevice = null;
        } elseif ($knownDevice === null && request()->hasSession() && ($rotation = DeviceCookie::rotation()) !== null) {
            // A sibling may have just rotated the shared cookie. Preserve this
            // guard's existing live identity; finalization rekeys it under lock.
            $prior = $this->findByHash($guard, $userType, $identifier, $rotation['from']);
            if ($prior !== null && ! $prior->isRevoked()) {
                $knownDevice = $prior;
            }
        }

        if ($knownDevice === null) {
            $rawToken = $rawToken ?? DeviceCookie::generateToken();

            $knownDevice = $this->createDevice(
                $guard,
                $userType,
                $identifier,
                DeviceCookie::hash($rawToken),
                $deviceName,
                $userAgent,
                $ip,
                $now,
            );

            $isNew = $knownDevice->wasRecentlyCreated;
            DeviceCookie::queue($rawToken);
        } else {
            $isNew = false;
        }

        if ($isNew) {
            $email = null;

            if ($user instanceof Model) {
                $value = $user->getAttribute('email');
                $email = is_string($value) && filled($value) ? $value : null;
            }

            SecurityEvent::record(
                SecurityEvent::TYPE_DEVICE_REGISTERED,
                $ip,
                $email,
                is_numeric($identifier) ? (int) $identifier : null,
                $guard,
                $deviceName,
                ['device_id' => $knownDevice->id],
            );
        }

        $this->markSeen($knownDevice, $ip, $userAgent, $deviceName, $now);

        $this->pruneInactiveDevices($user, $guard, $knownDevice->id);

        return [$knownDevice, $isNew];
    }

    /**
     * Map the current session onto the device (the mapping powers
     * "sign out device" and the per-device session count).
     */
    public function associateSession(Device $device, string $guard, string $sessionId): DeviceSession
    {
        return DeviceSession::query()->updateOrCreate(
            ['device_id' => $device->id, 'session_id' => $sessionId],
            ['guard' => $guard, 'last_seen_at' => Carbon::now()],
        );
    }

    /**
     * Associate every guard authenticated in a persisted session together.
     * If an identity was removed or revoked during login, reject the session.
     *
     * @param  list<Device|array{id: int, guard: string, user_type: string, user_identifier: string}>  $devices
     */
    public function associatePersistedSession(array $devices, string $sessionId, ?string $previousSessionId = null): bool
    {
        return DB::connection()->transaction(function () use ($devices, $sessionId, $previousSessionId): bool {
            $bindings = array_map(fn (Device | array $device): array => $device instanceof Device
                ? $this->sessionBinding($device)
                : $device, $devices);
            $lockedDevices = $this->lockDevices(Device::query()->whereKey(array_column($bindings, 'id')))->keyBy('id');

            foreach ($bindings as $binding) {
                $current = $lockedDevices->get($binding['id']);
                if ($current === null || $current->isRevoked() || $current->guard !== $binding['guard']
                    || $current->user_type !== $binding['user_type'] || $current->user_identifier !== $binding['user_identifier']) {
                    return false;
                }
            }

            if ($previousSessionId !== null && $previousSessionId !== $sessionId && config('session.driver') === 'database') {
                $sessionsTable = filament_loginguard_config_string('filament-loginguard.sessions.table', 'sessions');
                DeviceSession::query()->where('session_id', $previousSessionId)
                    ->whereNotIn('session_id', DB::table($sessionsTable)->select('id'))
                    ->delete();
            }

            $rotation = DeviceCookie::rotation();
            foreach ($lockedDevices as $device) {
                if ($rotation !== null && $device->token_hash === $rotation['from']) {
                    $device->forceFill(['token_hash' => $rotation['to']])->save();
                }
                $this->associateSession($device, $device->guard, $sessionId);
            }

            return true;
        });
    }

    /** @return array{id: int, guard: string, user_type: string, user_identifier: string} */
    public function sessionBinding(Device $device): array
    {
        return [
            'id' => $device->id,
            'guard' => $device->guard,
            'user_type' => $device->user_type,
            'user_identifier' => $device->user_identifier,
        ];
    }

    /**
     * Sign out (delete) every session mapped to the device except the current
     * one, and clean up their mappings. The device identity itself is kept —
     * signing out is a normal operation, not a security incident.
     */
    public function signOutDevice(Device $device, string $currentSessionId): int
    {
        $sessionsTable = filament_loginguard_config_string('filament-loginguard.sessions.table', 'sessions');

        $sessionIds = $device->sessions()
            ->pluck('session_id')
            ->reject(fn (string $sessionId): bool => $sessionId === $currentSessionId)
            ->values();

        if ($sessionIds->isEmpty()) {
            return 0;
        }

        // Delete the real Laravel session rows (that is what "sign out" means),
        // then the stale mappings.
        $deleted = DB::table($sessionsTable)
            ->whereIn('id', $sessionIds->all())
            ->delete();

        DeviceSession::query()
            ->whereIn('session_id', $sessionIds->all())
            ->delete();

        return (int) $deleted;
    }

    /**
     * Security-incident path: delete the device's real Laravel sessions before
     * removing their mappings, then revoke the identity and any device trust.
     * The current session is protected at the service boundary as well as in
     * the UI. Session deletion and identity changes share one transaction.
     */
    public function revoke(Device $device, string $reason = 'this_is_not_me'): void
    {
        $currentSessionId = filament_loginguard_session_id();

        $revoked = DB::transaction(function () use ($device, $currentSessionId): bool {
            if ($this->lockDevices(Device::query()->whereKey($device->id))->isEmpty()) {
                return false;
            }

            // Do not trust a client-supplied device hash to protect the current
            // session: check its server-side mapping before deleting anything.
            abort_if(
                $device->sessions()->where('session_id', $currentSessionId)->exists(),
                403,
            );

            // Reuse the existing session deletion path. Deleting only the
            // relationship would leave the authenticated session rows alive.
            $this->signOutDevice($device, $currentSessionId);

            // SessionGuard shares one remember token across the account's
            // devices. Rotate it on explicit revocation, leaving live sessions
            // on other devices untouched.
            $guard = Auth::guard($device->guard);
            if ($guard instanceof SessionGuard) {
                $provider = $guard->getProvider();
                $owner = $provider->retrieveById($device->user_identifier);
                if ($owner !== null && $owner::class === $device->user_type && filled($owner->getRememberToken())) {
                    $provider->updateRememberToken($owner, Str::random(60));
                }
            }

            return $device->forceFill([
                'revoked_at' => Carbon::now(),
                'trusted_at' => null,
            ])->save();
        });

        if (! $revoked) {
            return;
        }

        SecurityEvent::record(SecurityEvent::TYPE_DEVICE_REVOKED, null, null, null, $device->guard, $device->device_name, [
            'device_id' => $device->id,
            'reason' => $reason,
        ]);
    }

    /**
     * Normal removal: drop the identity so the next login from the same
     * browser starts as a NEW device. Used for devices with no live session.
     */
    public function forget(Device $device): void
    {
        $forgotten = DB::transaction(function () use ($device): bool {
            if ($this->lockDevices(Device::query()->whereKey($device->id))->isEmpty()) {
                return false;
            }

            abort_if($device->hasActiveSessions(), 409);

            return $device->delete() === true;
        });

        if (! $forgotten) {
            return;
        }

        SecurityEvent::record(SecurityEvent::TYPE_DEVICE_FORGOTTEN, null, null, null, $device->guard, $device->device_name, [
            'device_id' => $device->id,
        ]);
    }

    /**
     * Sign out every other session of the account. Only sessions are deleted —
     * device records and recognition are preserved (signing out everywhere is
     * NOT forgetting every device).
     *
     * @return int the number of other sessions that were removed
     */
    public function signOutOthers(Authenticatable $user, string $guard, string $userType, string $identifier, string $currentSessionId): int
    {
        $deviceIds = $this->devicesFor($guard, $userType, $identifier)
            ->pluck('id');

        $mappings = DeviceSession::query()
            ->whereIn('device_id', $deviceIds)
            ->where('session_id', '!=', $currentSessionId)
            ->pluck('session_id');

        if ($mappings->isEmpty()) {
            return 0;
        }

        $sessionsTable = filament_loginguard_config_string('filament-loginguard.sessions.table', 'sessions');

        // "Sign out" means deleting the real Laravel session rows, then the
        // stale mappings. Device identities are preserved.
        $deleted = DB::table($sessionsTable)
            ->whereIn('id', $mappings->all())
            ->delete();

        DeviceSession::query()
            ->whereIn('session_id', $mappings->all())
            ->delete();

        SecurityEvent::record(SecurityEvent::TYPE_SESSIONS_REVOKED_OTHERS, null, null, is_numeric($identifier) ? (int) $identifier : null, $guard, null, [
            'count' => $deleted,
        ]);

        return (int) $deleted;
    }

    /**
     * Email the account owner when a brand-new device identity signs in.
     */
    public function notifyNewDevice(Device $device, ?string $email): void
    {
        if (blank($email)) {
            return;
        }

        $notification = new NewDeviceLoginNotification(
            email: $email,
            device: $device->device_name ?? filament_loginguard_trans('filament-loginguard::loginguard.devices.unknown_device'),
            ip: $device->last_ip ?? '',
        );

        $queue = config('filament-loginguard.devices.notifications.mail.queue', false);
        $notifiable = Notification::route('mail', $email);

        if (is_string($queue) && $queue !== '') {
            $notifiable->notify($notification->onQueue($queue));
        } else {
            $notifiable->notifyNow($notification);
        }
    }

    /**
     * Hard cap of device identities per account: when exceeded, the oldest
     * devices without active sessions are removed.
     */
    public function enforceDeviceCap(Authenticatable $user, string $guard): void
    {
        $this->pruneInactiveDevices($user, $guard, null);
    }

    private function pruneInactiveDevices(Authenticatable $user, string $guard, ?int $currentDeviceId): void
    {
        $cap = filament_loginguard_config_int('filament-loginguard.devices.max_devices_per_user', 20);

        if ($cap <= 0) {
            return;
        }

        $userType = $user::class;
        $identifier = filament_loginguard_identifier($user->getAuthIdentifier());

        $devices = $this->devicesFor($guard, $userType, $identifier);
        $devices->whereNull('revoked_at');
        $excess = $devices->count() - $cap;

        if ($excess <= 0) {
            return;
        }

        if ($currentDeviceId !== null) {
            $devices->where('id', '!=', $currentDeviceId);
        }

        $devices->whereDoesntHave('sessions', function (Builder $query): void {
            // Other session drivers cannot be checked against the database.
            if (config('session.driver') === 'database') {
                $query->whereIn('session_id', DeviceSession::liveSessionIds());
            }
        });

        $ids = (clone $devices)->oldest('last_seen_at')->oldest('id')->limit($excess)->pluck('id');
        if ($ids->isEmpty()) {
            return;
        }

        DB::transaction(function () use ($devices, $ids): void {
            $this->lockDevices(Device::query()->whereKey($ids));
            // Recheck eligibility after acquiring the same locks as login finalization.
            $devices->whereKey($ids)->delete();
        });
    }

    /**
     * Remove device↔session mappings whose session no longer exists, and
     * devices that are beyond the retention window with no live sessions.
     */
    public function cleanup(): void
    {
        if (config('session.driver') === 'database') {
            DeviceSession::query()
                ->whereNotIn('session_id', DeviceSession::liveSessionIds())
                ->delete();
        }

        $retentionDays = filament_loginguard_config_int('filament-loginguard.devices.retention_days', 90);

        if ($retentionDays > 0) {
            Device::query()
                ->where('last_seen_at', '<', Carbon::now()->subDays($retentionDays))
                ->whereDoesntHave('sessions')
                ->delete();
        }
    }

    /**
     * Base query: every device row of one account.
     *
     * @return Builder<Device>
     */
    private function devicesFor(string $guard, string $userType, string $identifier): Builder
    {
        return Device::query()
            ->where('guard', $guard)
            ->where('user_type', $userType)
            ->where('user_identifier', $identifier);
    }

    /**
     * Lock device rows in the active transaction before inspecting their mappings.
     *
     * @param  Builder<Device>  $devices
     * @return Collection<int, Device>
     */
    private function lockDevices(Builder $devices): Collection
    {
        if (DB::connection()->getDriverName() === 'sqlite') {
            // A write first prevents a deferred read transaction from losing
            // its chance to acquire SQLite's writer lock.
            (clone $devices)->toBase()->update(['updated_at' => DB::raw('updated_at')]);
        }

        $devices->orderBy('id')->lockForUpdate();

        return $devices->get();
    }

    private function findByHash(string $guard, string $userType, string $identifier, string $hash): ?Device
    {
        return $this->devicesFor($guard, $userType, $identifier)
            ->where('token_hash', $hash)
            ->first();
    }

    private function createDevice(
        string $guard,
        string $userType,
        string $identifier,
        string $tokenHash,
        ?string $deviceName,
        ?string $userAgent,
        ?string $ip,
        Carbon $now,
    ): Device {
        try {
            return Device::query()->create([
                'guard' => $guard,
                'user_type' => $userType,
                'user_identifier' => $identifier,
                'token_hash' => $tokenHash,
                'device_name' => $deviceName,
                'user_agent' => $userAgent === null ? null : mb_substr($userAgent, 0, 1000),
                'first_ip' => $ip,
                'last_ip' => $ip,
                'first_seen_at' => $now,
                'last_seen_at' => $now,
            ]);
        } catch (UniqueConstraintViolationException) {
            // Two concurrent logins with the same fresh cookie: keep either row.
            return $this->devicesFor($guard, $userType, $identifier)
                ->where('token_hash', $tokenHash)
                ->firstOrFail();
        }
    }

    private function markSeen(Device $device, ?string $ip, ?string $userAgent, ?string $deviceName, Carbon $now): void
    {
        $device->forceFill([
            'last_seen_at' => $now,
            'last_ip' => $ip ?? $device->last_ip,
            'user_agent' => $userAgent === null ? $device->user_agent : mb_substr($userAgent, 0, 1000),
        ])->save();

        SecurityEvent::record(SecurityEvent::TYPE_DEVICE_SEEN, $ip, null, null, $device->guard, $deviceName, [
            'device_id' => $device->id,
        ]);
    }
}
