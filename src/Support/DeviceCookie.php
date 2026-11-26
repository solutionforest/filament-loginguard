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

    private const ROTATION = 'filament-loginguard.token-rotation';

    public static function name(): string
    {
        return filament_loginguard_config_string('filament-loginguard.devices.cookie.name', self::DEFAULT_NAME);
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

    public static function replaceRevokedToken(string $previousHash): string
    {
        $token = self::generateToken();
        request()->attributes->set(self::ROTATION, ['from' => $previousHash, 'to' => self::hash($token)]);

        return $token;
    }

    /** @return array{from: string, to: string}|null */
    public static function rotation(): ?array
    {
        $rotation = request()->attributes->all(self::ROTATION);
        $token = self::get();
        if (! is_string($rotation['from'] ?? null) || ! is_string($rotation['to'] ?? null)
            || $token === null || self::hash($token) !== $rotation['to']) {
            return null;
        }

        return ['from' => $rotation['from'], 'to' => $rotation['to']];
    }

    /**
     * Queue the cookie onto the response. Encryption is handled by Laravel's
     * EncryptCookies middleware (the cookie is not in the "except" list).
     */
    public static function queue(string $token): void
    {
        // A second guard can log in before the browser receives this response.
        // It must resolve against the identity we are issuing, including a
        // replacement token when the incoming identity was revoked.
        request()->cookies->set(self::name(), $token);

        Cookie::queue(
            self::name(),
            $token,
            filament_loginguard_config_int('filament-loginguard.devices.cookie.lifetime_days', 365) * 24 * 60,
            '/',
            null,
            null, // secure follows the app's session/URL config
            true, // httpOnly
            false,
            filament_loginguard_config_string('filament-loginguard.devices.cookie.same_site', 'lax'),
        );
    }

    public static function forget(): void
    {
        Cookie::queue(Cookie::forget(self::name(), '/'));
    }

    /**
     * Generate a new opaque token.
     */
    public static function generateToken(): string
    {
        return bin2hex(random_bytes(32));
    }
}
