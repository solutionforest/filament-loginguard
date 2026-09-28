<?php

namespace SolutionForest\FilamentLoginGuard\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;

final class AuthorizesPages
{
    /**
     * Check a gate ability for the current user. A blank ability (or a missing
     * ability that defaults to allowed in Laravel's Gate) passes.
     */
    public static function allows(?string $ability): bool
    {
        if (blank($ability)) {
            return true;
        }

        $user = Auth::user();

        return $user instanceof Authenticatable
            && method_exists($user, 'can')
            && (bool) $user->can($ability);
    }

    /**
     * Whether the current user may VIEW the attempts page. Falls back to the
     * generic `authorize` ability when no view-specific ability is set.
     */
    public static function canViewAttempts(): bool
    {
        return self::allows(self::ability('pages.attempts.authorize_view', 'pages.attempts.authorize'));
    }

    /**
     * Whether the current user may UNBLOCK locked attempts. Falls back to the
     * view ability when no unblock-specific ability is set, so a single
     * `authorize` key keeps granting full control.
     */
    public static function canUnblockAttempts(): bool
    {
        return self::allows(self::ability('pages.attempts.authorize_unblock', 'pages.attempts.authorize_view', 'pages.attempts.authorize'));
    }

    /**
     * Whether the current user may VIEW the sessions page.
     */
    public static function canViewSessions(): bool
    {
        return self::allows(self::ability('pages.sessions.authorize_view', 'pages.sessions.authorize'));
    }

    /**
     * Whether the current user may REVOKE sessions.
     */
    public static function canRevokeSessions(): bool
    {
        return self::allows(self::ability('pages.sessions.authorize_revoke', 'pages.sessions.authorize_view', 'pages.sessions.authorize'));
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
