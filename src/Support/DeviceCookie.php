<?php

namespace SolutionForest\FilamentLoginGuard\Support;

use Illuminate\Support\Facades\Cookie;

/**
 * The opaque device token cookie. The raw token lives exclusively in the
 * browser; the database only ever sees its SHA-256 hash.
 */
final class DeviceCookie
{
    public const DEFAULT_NAME = 'filament_loginguard_device';

    public static function name(): string
    {
        return (string) config('filament-loginguard.devices.cookie.name', self::DEFAULT_NAME);
    }

    /**
     * The raw token from the current request, or null when absent.
     */
    public static function get(): ?string
    {
        $token = request()->cookie(self::name());

        return is_string($token) && $token !== '' ? $token : null;
    }

    public static function hash(string $token): string
    {
        return hash('sha256', $token);
    }

    /**
     * Queue the cookie onto the response. Encryption is handled by Laravel's
     * EncryptCookies middleware (the cookie is not in the "except" list).
     */
    public static function queue(string $token): void
    {
        Cookie::queue(
            self::name(),
            $token,
            (int) config('filament-loginguard.devices.cookie.lifetime_days', 365) * 24 * 60,
            '/',
            null,
            null, // secure follows the app's session/URL config
            true, // httpOnly
            false,
            (string) config('filament-loginguard.devices.cookie.same_site', 'lax'),
        );
    }

    public static function forget(): void
    {
        Cookie::queue(Cookie::forget(self::name()));
    }

    /**
     * Generate a new opaque token.
     */
    public static function generateToken(): string
    {
        return bin2hex(random_bytes(32));
    }
}
