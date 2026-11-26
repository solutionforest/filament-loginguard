<?php

declare(strict_types=1);
use Illuminate\Session\Store;

if (! function_exists('filament_loginguard_trans')) {
    /**
     * Translate a package string, always returning a string (never an array).
     *
     * @param  array<string, mixed>  $replace
     */
    function filament_loginguard_trans(string $key, array $replace = [], ?string $locale = null): string
    {
        $line = trans($key, $replace, $locale);

        return is_string($line) ? $line : $key;
    }
}

if (! function_exists('filament_loginguard_trans_choice')) {
    /**
     * Translate a pluralized package string, always returning a string.
     *
     * @param  array<string, mixed>  $replace
     */
    function filament_loginguard_trans_choice(string $key, int $number, array $replace = [], ?string $locale = null): string
    {
        return trans_choice($key, $number, $replace, $locale);
    }
}

if (! function_exists('filament_loginguard_config_int')) {
    /**
     * Read an integer config value, falling back to a default when unset or
     * not an integer.
     */
    function filament_loginguard_config_int(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_int($value) ? $value : $default;
    }
}

if (! function_exists('filament_loginguard_config_string')) {
    /**
     * Read a string config value, falling back to a default when unset, empty
     * or not a string.
     */
    function filament_loginguard_config_string(string $key, string $default = ''): string
    {
        $value = config($key);

        return is_string($value) && $value !== '' ? $value : $default;
    }
}

if (! function_exists('filament_loginguard_identifier')) {
    /**
     * Stringify an auth identifier (int, string or UUID) safely.
     */
    function filament_loginguard_identifier(mixed $value): string
    {
        return is_string($value) || is_int($value) ? (string) $value : '';
    }
}

if (! function_exists('filament_loginguard_intval')) {
    /**
     * Coerce a scalar value to int, returning 0 for anything non-numeric
     * (arrays, objects, null) that intval() itself would not accept cleanly.
     */
    function filament_loginguard_intval(mixed $value): int
    {
        return is_int($value) || is_float($value) || is_string($value) || is_bool($value)
            ? (int) $value
            : 0;
    }
}

if (! function_exists('filament_loginguard_session_id')) {
    /**
     * The current session ID from the session store, or an empty string when
     * no session store is available.
     */
    function filament_loginguard_session_id(): string
    {
        $store = app('session.store');

        if (! $store instanceof Store) {
            return '';
        }

        return $store->getId();
    }
}
