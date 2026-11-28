<?php

namespace SolutionForest\FilamentLoginGuard\Support;

use Closure;
use Filament\Facades\Filament;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;
use SolutionForest\FilamentLoginGuard\FilamentLoginGuardPlugin;

final class AuthorizesPages
{
    /**
     * A blank ability allows access. A configured ability is checked against
     * the current panel's authenticated user (falling back to the default guard).
     */
    public static function allows(?string $ability): bool
    {
        if (blank($ability)) {
            return true;
        }

        $user = self::currentUser();

        return $user instanceof Authenticatable
            && method_exists($user, 'can')
            && (bool) $user->can($ability);
    }

    /**
     * Whether the current user may VIEW the attempts page. Checks any per-panel
     * plugin callback first, then falls back to `pages.attempts.authorize_view` / `authorize`.
     */
    public static function canViewAttempts(): bool
    {
        $callback = FilamentLoginGuardPlugin::current()?->getAuthorizeAttemptsCallback();

        if ($callback instanceof Closure) {
            return self::evaluateCallback($callback);
        }

        return self::allows(self::ability('pages.attempts.authorize_view', 'pages.attempts.authorize'));
    }

    /**
     * Whether the current user may UNBLOCK locked attempts. Checks any per-panel
     * plugin callback first, then falls back to config abilities.
     */
    public static function canUnblockAttempts(): bool
    {
        $callback = FilamentLoginGuardPlugin::current()?->getAuthorizeUnblockCallback();

        if ($callback instanceof Closure) {
            return self::evaluateCallback($callback);
        }

        return self::allows(self::ability('pages.attempts.authorize_unblock', 'pages.attempts.authorize_view', 'pages.attempts.authorize'));
    }

    /**
     * Whether the current user may VIEW the sessions page.
     */
    public static function canViewSessions(): bool
    {
        $callback = FilamentLoginGuardPlugin::current()?->getAuthorizeSessionsCallback();

        if ($callback instanceof Closure) {
            return self::evaluateCallback($callback);
        }

        return self::allows(self::ability('pages.sessions.authorize_view', 'pages.sessions.authorize'));
    }

    /**
     * Whether the current user may REVOKE sessions.
     */
    public static function canRevokeSessions(): bool
    {
        $callback = FilamentLoginGuardPlugin::current()?->getAuthorizeRevokeCallback();

        if ($callback instanceof Closure) {
            return self::evaluateCallback($callback);
        }

        return self::allows(self::ability('pages.sessions.authorize_revoke', 'pages.sessions.authorize_view', 'pages.sessions.authorize'));
    }

    /**
     * @param  Closure(Authenticatable): bool  $callback
     */
    private static function evaluateCallback(Closure $callback): bool
    {
        $user = self::currentUser();

        return $user instanceof Authenticatable && (bool) $callback($user);
    }

    private static function currentUser(): ?Authenticatable
    {
        $panel = Filament::getCurrentPanel();

        if ($panel !== null) {
            $panelUser = Filament::auth()->user();

            if ($panelUser instanceof Authenticatable) {
                return $panelUser;
            }
        }

        return Auth::user();
    }

    /**
     * First configured (non-null) config key wins.
     */
    private static function ability(string ...$keys): ?string
    {
        foreach ($keys as $key) {
            $value = config("filament-loginguard.{$key}");

            if (is_string($value) && filled($value)) {
                return $value;
            }
        }

        return null;
    }
}
