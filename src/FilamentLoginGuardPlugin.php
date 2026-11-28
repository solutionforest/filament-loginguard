<?php

namespace SolutionForest\FilamentLoginGuard;

use Closure;
use Filament\Actions\Action;
use Filament\Contracts\Plugin;
use Filament\Facades\Filament;
use Filament\Panel;
use Filament\Support\Icons\Heroicon;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Route;
use SolutionForest\FilamentLoginGuard\Pages\LoginGuard;
use SolutionForest\FilamentLoginGuard\Pages\MyDevices;
use SolutionForest\FilamentLoginGuard\Pages\UserSessions;

class FilamentLoginGuardPlugin implements Plugin
{
    protected ?bool $loginGuardPageEnabled = null;

    protected ?bool $userSessionsPageEnabled = null;

    protected ?bool $myDevicesPageEnabled = null;

    protected ?bool $myDevicesUserMenuEnabled = null;

    /** @var (Closure(Authenticatable): bool)|null */
    protected ?Closure $authorizeAttemptsUsing = null;

    /** @var (Closure(Authenticatable): bool)|null */
    protected ?Closure $authorizeUnblockUsing = null;

    /** @var (Closure(Authenticatable): bool)|null */
    protected ?Closure $authorizeSessionsUsing = null;

    /** @var (Closure(Authenticatable): bool)|null */
    protected ?Closure $authorizeRevokeUsing = null;

    public function getId(): string
    {
        return 'filament-loginguard';
    }

    public function loginGuardPage(bool $condition = true): static
    {
        $this->loginGuardPageEnabled = $condition;

        return $this;
    }

    public function userSessionsPage(bool $condition = true): static
    {
        $this->userSessionsPageEnabled = $condition;

        return $this;
    }

    public function myDevicesPage(bool $condition = true, ?bool $userMenu = null): static
    {
        $this->myDevicesPageEnabled = $condition;

        if ($userMenu !== null) {
            $this->myDevicesUserMenuEnabled = $userMenu;
        }

        return $this;
    }

    /**
     * @param  (Closure(Authenticatable): bool)|null  $callback
     */
    public function authorizeAttemptsUsing(?Closure $callback): static
    {
        $this->authorizeAttemptsUsing = $callback;

        return $this;
    }

    /**
     * @param  (Closure(Authenticatable): bool)|null  $callback
     */
    public function authorizeUnblockUsing(?Closure $callback): static
    {
        $this->authorizeUnblockUsing = $callback;

        return $this;
    }

    /**
     * @param  (Closure(Authenticatable): bool)|null  $callback
     */
    public function authorizeSessionsUsing(?Closure $callback): static
    {
        $this->authorizeSessionsUsing = $callback;

        return $this;
    }

    /**
     * @param  (Closure(Authenticatable): bool)|null  $callback
     */
    public function authorizeRevokeUsing(?Closure $callback): static
    {
        $this->authorizeRevokeUsing = $callback;

        return $this;
    }

    public function hasLoginGuardPage(): bool
    {
        return $this->loginGuardPageEnabled ?? (bool) config('filament-loginguard.pages.attempts.enabled', true);
    }

    public function hasUserSessionsPage(): bool
    {
        return $this->userSessionsPageEnabled ?? (bool) config('filament-loginguard.pages.sessions.enabled', true);
    }

    public function hasMyDevicesPage(): bool
    {
        return $this->myDevicesPageEnabled ?? (bool) config('filament-loginguard.pages.my_devices.enabled', true);
    }

    public function showsMyDevicesInUserMenu(): bool
    {
        return $this->myDevicesUserMenuEnabled ?? (bool) config('filament-loginguard.pages.my_devices.user_menu', true);
    }

    /**
     * @return (Closure(Authenticatable): bool)|null
     */
    public function getAuthorizeAttemptsCallback(): ?Closure
    {
        return $this->authorizeAttemptsUsing;
    }

    /**
     * @return (Closure(Authenticatable): bool)|null
     */
    public function getAuthorizeUnblockCallback(): ?Closure
    {
        return $this->authorizeUnblockUsing ?? $this->authorizeAttemptsUsing;
    }

    /**
     * @return (Closure(Authenticatable): bool)|null
     */
    public function getAuthorizeSessionsCallback(): ?Closure
    {
        return $this->authorizeSessionsUsing;
    }

    /**
     * @return (Closure(Authenticatable): bool)|null
     */
    public function getAuthorizeRevokeCallback(): ?Closure
    {
        return $this->authorizeRevokeUsing ?? $this->authorizeSessionsUsing;
    }

    public function register(Panel $panel): void
    {
        $pages = [];

        if ($this->loginGuardPageEnabled !== false) {
            $pages[] = LoginGuard::class;
        }

        if ($this->userSessionsPageEnabled !== false) {
            $pages[] = UserSessions::class;
        }

        if ($this->myDevicesPageEnabled !== false) {
            $pages[] = MyDevices::class;

            // Register the self-service My Devices link once per panel with lazy URL & visibility
            // closures so: (1) panels without this plugin are untouched, (2) tenant panels never
            // throw before a tenant is resolved (e.g. on /login), and (3) Octane never duplicates items.
            $panel->userMenuItems([
                'filament-loginguard-my-devices' => Action::make('filament-loginguard-my-devices')
                    ->label(static fn (): string => filament_loginguard_trans('filament-loginguard::loginguard.my_devices.title'))
                    ->icon(Heroicon::DevicePhoneMobile)
                    ->url(static function () use ($panel): string {
                        if ($panel->hasTenancy() && Filament::getTenant() === null) {
                            return '#';
                        }

                        $routeName = MyDevices::getRouteName($panel);

                        if (! Route::has($routeName)) {
                            return '#';
                        }

                        return MyDevices::getUrl();
                    })
                    ->visible(function () use ($panel): bool {
                        if (! $this->hasMyDevicesPage() || ! $this->showsMyDevicesInUserMenu()) {
                            return false;
                        }

                        if ($panel->hasTenancy() && Filament::getTenant() === null) {
                            return false;
                        }

                        return MyDevices::canAccess();
                    })
                    ->sort(2),
            ]);
        }

        if ($pages !== []) {
            $panel->pages($pages);
        }
    }

    public function boot(Panel $panel): void
    {
        //
    }

    public static function make(): static
    {
        return app(static::class);
    }

    public static function get(): static
    {
        /** @var static $plugin */
        $plugin = filament(app(static::class)->getId());

        return $plugin;
    }

    /**
     * Return this plugin instance for the currently active panel, or null when no
     * panel is active or the active panel does not register FilamentLoginGuardPlugin.
     */
    public static function current(): ?static
    {
        $panel = Filament::getCurrentPanel();

        if (! $panel instanceof Panel) {
            return null;
        }

        $id = app(static::class)->getId();

        if (! $panel->hasPlugin($id)) {
            return null;
        }

        $plugin = $panel->getPlugin($id);

        return $plugin instanceof static ? $plugin : null;
    }
}
