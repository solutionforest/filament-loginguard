<?php

namespace SolutionForest\FilamentLoginGuard\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
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
     * @param  object  $user  the authenticated user (getAuthIdentifier + getMorphClass)
     * @return array{0: Device, 1: bool}
     */
    public function resolveOrCreate(object $user, string $guard, ?string $userAgent, ?string $ip): array
    {
        $userType = $user::class;
        $identifier = (string) $user->getAuthIdentifier();
        $now = Carbon::now();
        $deviceName = ParsesUserAgent::parseDeviceName($userAgent);

        $rawToken = DeviceCookie::get();
        $knownDevice = $rawToken !== null
            ? $this->findByToken($guard, $userType, $identifier, $rawToken)
            : null;

        // A revoked token must never silently become recognized again; the
        // browser gets a fresh identity on the next login.
        if ($knownDevice !== null && $knownDevice->isRevoked()) {
            $knownDevice = null;
            $rawToken = null;
        }

        if ($knownDevice === null) {
            $isNew = true;
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

            DeviceCookie::queue($rawToken);

            SecurityEvent::record(
                SecurityEvent::TYPE_DEVICE_REGISTERED,
                $ip,
                is_callable([$user, 'getAttribute']) ? ($user->getAttribute('email') ?? null) : null,
                is_numeric($identifier) ? (int) $identifier : null,
                $guard,
                $deviceName,
                ['device_id' => $knownDevice->id],
            );
        } else {
            $isNew = false;
        }

        $this->markSeen($knownDevice, $ip, $userAgent, $deviceName, $now);

        $this->enforceDeviceCap($user, $guard);

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
     * Sign out (delete) every session mapped to the device except the current
     * one, and clean up their mappings. The device identity itself is kept —
     * signing out is a normal operation, not a security incident.
     */
    public function signOutDevice(Device $device, string $currentSessionId): int
    {
        $sessionsTable = (string) config('filament-loginguard.sessions.table', 'sessions');

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
     * Security-incident path: revoke all the device's sessions and mark the
     * device itself revoked. The token will never silently become recognized
     * again — the next login from the same cookie creates a fresh identity.
     */
    public function revoke(Device $device, string $reason = 'this_is_not_me'): void
    {
        $device->sessions()->delete();
        $device->forceFill(['revoked_at' => Carbon::now()])->save();

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
        $device->delete();

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
    public function signOutOthers(object $user, string $guard, string $userType, string $identifier, string $currentSessionId): int
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

        $sessionsTable = (string) config('filament-loginguard.sessions.table', 'sessions');

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
            device: $device->device_name ?? __('filament-loginguard::loginguard.devices.unknown_device'),
            ip: $device->last_ip ?? '',
        );

        $queue = config('filament-loginguard.devices.notifications.mail.queue', false);
        $notifiable = Notification::route('mail', $email);

        if ($queue !== false) {
            $notifiable->notify($notification->onQueue((string) $queue));
        } else {
            $notifiable->notifyNow($notification);
        }
    }

    /**
     * Hard cap of device identities per account: when exceeded, the oldest
     * devices without active sessions are removed.
     */
    public function enforceDeviceCap(object $user, string $guard): void
    {
        $cap = (int) config('filament-loginguard.devices.max_devices_per_user', 20);

        if ($cap <= 0) {
            return;
        }

        $userType = $user::class;
        $identifier = (string) $user->getAuthIdentifier();

        $devices = $this->devicesFor($guard, $userType, $identifier)
            ->whereNull('revoked_at')
            ->orderByDesc('last_seen_at')
            ->get();

        if ($devices->count() <= $cap) {
            return;
        }

        // Remove the least-recently-seen devices that have no sessions.
        $devices->slice($cap)
            ->each(fn (Device $device) => $device->delete());
    }

    /**
     * Remove device↔session mappings whose session no longer exists, and
     * devices that are beyond the retention window with no live sessions.
     */
    public function cleanup(): void
    {
        $sessionsTable = (string) config('filament-loginguard.sessions.table', 'sessions');

        // Mappings pointing at dead sessions.
        DeviceSession::query()
            ->whereNotExists(function ($query) use ($sessionsTable): void {
                $query->selectRaw(1)
                    ->from($sessionsTable)
                    ->whereColumn($sessionsTable . '.id', 'filament_loginguard_device_sessions.session_id');
            })
            ->delete();

        $retentionDays = (int) config('filament-loginguard.devices.retention_days', 90);

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

    private function findByToken(string $guard, string $userType, string $identifier, string $rawToken): ?Device
    {
        return $this->devicesFor($guard, $userType, $identifier)
            ->where('token_hash', DeviceCookie::hash($rawToken))
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
