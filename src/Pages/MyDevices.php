<?php

namespace SolutionForest\FilamentLoginGuard\Pages;

use Filament\Actions\Action;
use Filament\Facades\Filament;
use Filament\Notifications\Notification;
use Filament\Pages\Page;
use Filament\Support\Enums\Width;
use Illuminate\Contracts\View\View;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use SolutionForest\FilamentLoginGuard\Models\Device;
use SolutionForest\FilamentLoginGuard\Models\DeviceSession;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;
use SolutionForest\FilamentLoginGuard\Services\DeviceManager;
use SolutionForest\FilamentLoginGuard\Support\DeviceCookie;
use SolutionForest\FilamentLoginGuard\Support\ParsesUserAgent;

/**
 * Self-service account security: the devices (and their sessions) that belong
 * to the currently authenticated user. The query is ALWAYS scoped server-side
 * to the current guard + user — there is no user_id parameter anywhere.
 */
class MyDevices extends Page
{
    protected string $view = 'filament-loginguard::pages.my-devices';

    /**
     * Constrain the whole page (header + content) to a single alignment line,
     * so the "Sign out other sessions" button lines up with the device list.
     */
    protected Width | string | null $maxContentWidth = Width::FiveExtraLarge;

    public function getTitle(): string
    {
        return __('filament-loginguard::loginguard.my_devices.title');
    }

    public function getHeading(): string
    {
        return __('filament-loginguard::loginguard.my_devices.heading');
    }

    public static function canAccess(): bool
    {
        return (bool) config('filament-loginguard.pages.my_devices.enabled', true)
            && (bool) config('filament-loginguard.devices.enabled', true)
            && Filament::auth()->user() !== null;
    }

    public static function shouldRegisterNavigation(): bool
    {
        return (bool) config('filament-loginguard.pages.my_devices.navigation', false)
            && static::canAccess();
    }

    public static function getDefaultSlug(): string
    {
        return (string) (config('filament-loginguard.pages.my_devices.slug') ?: 'my-devices');
    }

    public static function getNavigationLabel(): string
    {
        return (string) (config('filament-loginguard.pages.my_devices.navigation_label')
            ?: __('filament-loginguard::loginguard.my_devices.navigation_label'));
    }

    public static function getNavigationIcon(): string
    {
        return (string) (config('filament-loginguard.pages.my_devices.navigation_icon')
            ?: 'heroicon-o-device-phone-mobile');
    }

    public static function getNavigationGroup(): ?string
    {
        $group = config('filament-loginguard.pages.my_devices.navigation_group');

        return is_string($group) ? $group : null;
    }

    public static function getNavigationSort(): ?int
    {
        $sort = config('filament-loginguard.pages.my_devices.navigation_sort');

        return is_int($sort) ? $sort : null;
    }

    /**
     * The token hash of the current browser, so its card can be pinned on top.
     */
    public ?string $currentDeviceHash = null;

    public function mount(): void
    {
        $this->currentDeviceHash = $this->currentTokenHash();
    }

    protected function currentTokenHash(): ?string
    {
        $token = DeviceCookie::get();

        return $token !== null ? DeviceCookie::hash($token) : null;
    }

    /**
     * @return array{string, string, string} [user class, guard, identifier]
     */
    protected function currentUserContext(): array
    {
        $user = Filament::auth()->user();
        $guard = Filament::getCurrentPanel()?->getAuthGuard() ?? 'web';

        return [
            $user::class,
            $guard,
            (string) $user->getAuthIdentifier(),
        ];
    }

    /**
     * [current, active, previous, guard].
     *
     * "active" means another device with at least one live session; "previous"
     * means a device with no live session (signed out, expired or revoked) —
     * so the page never claims a device is online just because it is known.
     *
     * @return array{Device|null, Collection<int, Device>, Collection<int, Device>, string}
     */
    public function getDevicesProperty(): array
    {
        [$userType, $guard, $identifier] = $this->currentUserContext();

        /** @var Collection<int, Device> $all */
        $all = $this->ownedDevicesQuery($guard, $userType, $identifier)
            ->orderByDesc('last_seen_at')
            ->get();

        $current = $all->first(fn (Device $device): bool => $device->token_hash === $this->currentDeviceHash);
        $rest = $all->reject(fn (Device $device): bool => $device->is($current))->values();

        $liveIds = $this->liveSessionDeviceIds($rest);

        $active = $rest->filter(fn (Device $device): bool => in_array((int) $device->getKey(), $liveIds, true))->values();
        $previous = $rest->filter(fn (Device $device): bool => ! in_array((int) $device->getKey(), $liveIds, true))->values();

        return [$current, $active, $previous, $guard];
    }

    /**
     * Number of devices that are currently signed in (this device + others
     * with live sessions). Drives the low-emphasis summary under the title.
     */
    public function signedInCount(): int
    {
        [$current, $active] = $this->devicesCollection();

        return $active->count() + ($current !== null ? 1 : 0);
    }

    public function getSummaryProperty(): string
    {
        $count = $this->signedInCount();

        return trans_choice('filament-loginguard::loginguard.my_devices.signed_in_count', $count, ['count' => $count]);
    }

    /**
     * @return array{Device|null, Collection<int, Device>, Collection<int, Device>, string}
     */
    public function devicesCollection(): array
    {
        return $this->getDevicesProperty();
    }

    /**
     * The heroicon to represent a device, based only on reliable type data.
     * Scripts / bots / unknown clients get a terminal icon, never a phone.
     */
    public function deviceIcon(?string $userAgent): string
    {
        return match (ParsesUserAgent::parseDeviceType($userAgent)) {
            'desktop' => 'heroicon-o-computer-desktop',
            'mobile' => 'heroicon-o-device-phone-mobile',
            'tablet' => 'heroicon-o-device-tablet',
            default => 'heroicon-o-command-line',
        };
    }

    /**
     * The human-readable device name for the slide-over and list.
     */
    public function deviceLabel(Device $device): string
    {
        return $device->device_name ?? __('filament-loginguard::loginguard.devices.unknown_device');
    }

    /**
     * Live session count for a device (rows that still exist and are fresh).
     */
    public function liveSessionCount(Device $device): int
    {
        $sessionsTable = (string) config('filament-loginguard.sessions.table', 'sessions');
        $cutoff = now()->subMinutes((int) config('session.lifetime', 120))->getTimestamp();

        return $device->sessions()
            ->join($sessionsTable, 'filament_loginguard_device_sessions.session_id', '=', $sessionsTable . '.id')
            ->where($sessionsTable . '.last_activity', '>=', $cutoff)
            ->count();
    }

    /**
     * Device ids (from the given set) that still have a live session — one query.
     *
     * @param  Collection<int, Device>  $devices
     * @return array<int, int>
     */
    protected function liveSessionDeviceIds(Collection $devices): array
    {
        if ($devices->isEmpty()) {
            return [];
        }

        $sessionsTable = (string) config('filament-loginguard.sessions.table', 'sessions');
        $cutoff = now()->subMinutes((int) config('session.lifetime', 120))->getTimestamp();

        return DeviceSession::query()
            ->whereIn('device_id', $devices->pluck('id')->all())
            ->join($sessionsTable, 'filament_loginguard_device_sessions.session_id', '=', $sessionsTable . '.id')
            ->where($sessionsTable . '.last_activity', '>=', $cutoff)
            ->distinct()
            ->pluck('device_id')
            ->map(fn ($id): int => (int) $id)
            ->all();
    }

    protected function getHeaderActions(): array
    {
        return [
            Action::make('signOutOthers')
                ->label(__('filament-loginguard::loginguard.my_devices.actions.sign_out_others'))
                ->color('gray')
                ->requiresConfirmation()
                ->modalHeading(__('filament-loginguard::loginguard.my_devices.actions.sign_out_others_heading'))
                ->modalDescription(fn (): string => __('filament-loginguard::loginguard.my_devices.actions.sign_out_others_confirm', [
                    'count' => $this->otherSessionCount(),
                ]))
                ->visible(fn (): bool => $this->otherSessionCount() > 0)
                ->action(function (): void {
                    [$userType, $guard, $identifier] = $this->currentUserContext();

                    app(DeviceManager::class)->signOutOthers(
                        Filament::auth()->user(),
                        $guard,
                        $userType,
                        $identifier,
                        (string) app('session.store')->getId(),
                    );

                    Notification::make()
                        ->title(__('filament-loginguard::loginguard.my_devices.notifications.signed_out_others'))
                        ->success()
                        ->send();
                }),
        ];
    }

    /**
     * Read-only slide-over with the device details the user is allowed to see.
     */
    public function viewDeviceAction(): Action
    {
        return Action::make('viewDevice')
            ->label(__('filament-loginguard::loginguard.my_devices.actions.view_details'))
            ->slideOver()
            ->modalWidth('md')
            ->modalHeading(function (array $arguments): string {
                $device = $this->ownedDevice((string) ($arguments['device'] ?? ''));

                return $device !== null
                    ? $this->deviceLabel($device)
                    : __('filament-loginguard::loginguard.devices.unknown_device');
            })
            ->modalContent(function (array $arguments): View {
                $device = $this->ownedDevice((string) ($arguments['device'] ?? ''));

                return view('filament-loginguard::pages.my-devices-details', [
                    'device' => $device,
                    'browser' => $device !== null ? ParsesUserAgent::parseBrowserName($device->user_agent) : null,
                    'os' => $device !== null ? ParsesUserAgent::parseOsName($device->user_agent) : null,
                    'sessionCount' => $device !== null ? $this->liveSessionCount($device) : 0,
                ]);
            })
            ->modalSubmitAction(false)
            ->modalCancelActionLabel(__('filament-loginguard::loginguard.my_devices.actions.close'));
    }

    /**
     * Sign out: a normal operation — sessions die, the device stays recognized.
     */
    public function signOutDeviceAction(): Action
    {
        return Action::make('signOutDevice')
            ->label(__('filament-loginguard::loginguard.my_devices.actions.sign_out'))
            ->color('gray')
            ->icon('heroicon-m-arrow-left-on-rectangle')
            ->requiresConfirmation()
            ->modalHeading(__('filament-loginguard::loginguard.my_devices.actions.sign_out_heading'))
            ->modalDescription(__('filament-loginguard::loginguard.my_devices.actions.sign_out_description'))
            ->action(function (array $arguments): void {
                $device = $this->actionableDevice($arguments);

                if ($device === null || $this->isCurrentDevice($device)) {
                    return;
                }

                app(DeviceManager::class)->signOutDevice($device, (string) app('session.store')->getId());

                SecurityEvent::record(SecurityEvent::TYPE_SESSION_REVOKED_BY_USER, $device->last_ip, null, null, $device->guard, $device->device_name, [
                    'device_id' => $device->id,
                ]);

                Notification::make()
                    ->title(__('filament-loginguard::loginguard.my_devices.notifications.signed_out'))
                    ->success()
                    ->send();
            });
    }

    /**
     * Security incident: revoke all sessions + the device identity.
     */
    public function revokeDeviceAction(): Action
    {
        return Action::make('revokeDevice')
            ->label(__('filament-loginguard::loginguard.my_devices.actions.this_is_not_me'))
            ->color('danger')
            ->icon('heroicon-m-exclamation-triangle')
            ->requiresConfirmation()
            ->modalHeading(__('filament-loginguard::loginguard.my_devices.actions.this_is_not_me_heading'))
            ->modalDescription(__('filament-loginguard::loginguard.my_devices.actions.this_is_not_me_description'))
            ->action(function (array $arguments): void {
                $device = $this->actionableDevice($arguments);

                if ($device === null || $this->isCurrentDevice($device)) {
                    return;
                }

                app(DeviceManager::class)->revoke($device, reason: 'this_is_not_me');

                Notification::make()
                    ->title(__('filament-loginguard::loginguard.my_devices.notifications.revoked'))
                    ->success()
                    ->send();
            });
    }

    /**
     * Normal removal of a device that has no live session.
     */
    public function forgetDeviceAction(): Action
    {
        return Action::make('forgetDevice')
            ->label(__('filament-loginguard::loginguard.my_devices.actions.forget'))
            ->color('gray')
            ->icon('heroicon-m-trash')
            ->requiresConfirmation()
            ->modalHeading(__('filament-loginguard::loginguard.my_devices.actions.forget_heading'))
            ->modalDescription(__('filament-loginguard::loginguard.my_devices.actions.forget_description'))
            ->action(function (array $arguments): void {
                $device = $this->ownedDevice((string) ($arguments['device'] ?? ''));

                if ($device === null || $this->isCurrentDevice($device)) {
                    return;
                }

                app(DeviceManager::class)->forget($device);

                Notification::make()
                    ->title(__('filament-loginguard::loginguard.my_devices.notifications.forgotten'))
                    ->success()
                    ->send();
            });
    }

    public function otherSessionCount(): int
    {
        [$userType, $guard, $identifier] = $this->currentUserContext();
        $currentSessionId = (string) app('session.store')->getId();

        $deviceIds = $this->ownedDevicesQuery($guard, $userType, $identifier)
            ->pluck('id');

        return DeviceSession::query()
            ->whereIn('device_id', $deviceIds)
            ->where('session_id', '!=', $currentSessionId)
            ->count();
    }

    /**
     * The device from an action's `device` argument, ownership-checked and
     * guaranteed to not be the current device.
     */
    private function actionableDevice(array $arguments): ?Device
    {
        $device = $this->ownedDevice((string) ($arguments['device'] ?? ''));

        if ($device === null || $this->isCurrentDevice($device)) {
            return null;
        }

        return $device;
    }

    private function isCurrentDevice(Device $device): bool
    {
        $current = $this->devicesCollection()[0];

        return $current !== null && $current->is($device);
    }

    /**
     * Base query: every device row of the current account (ownership scope).
     *
     * @return Builder<Device>
     */
    private function ownedDevicesQuery(string $guard, string $userType, string $identifier): Builder
    {
        $query = Device::query();

        return $query
            ->where('guard', $guard)
            ->where('user_type', $userType)
            ->where('user_identifier', $identifier);
    }

    /**
     * Ownership guard: only devices of the current (guard, user) are ever
     * actionable. Returns null otherwise.
     */
    private function ownedDevice(string $deviceId): ?Device
    {
        [$userType, $guard, $identifier] = $this->currentUserContext();

        return $this->ownedDevicesQuery($guard, $userType, $identifier)
            ->whereKey($deviceId)
            ->first();
    }
}
