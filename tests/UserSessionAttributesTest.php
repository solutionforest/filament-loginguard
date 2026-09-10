<?php

use Carbon\Carbon;
use SolutionForest\FilamentLoginGuard\Models\KnownDevice;
use SolutionForest\FilamentLoginGuard\Models\UserSession;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;

beforeEach(function () {
    Carbon::setTestNow('2026-01-01 00:00:00');

    config()->set('auth.providers.users.model', User::class);
});

afterEach(function () {
    Carbon::setTestNow(null);
});

it('resolves the user email from the configured user model', function () {
    $user = UserFactory::new()->create(['email' => 'session-owner@example.com']);

    $session = UserSession::query()->create([
        'id' => 'session-known-user',
        'user_id' => $user->id,
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    expect($session->user_email)->toBe('session-owner@example.com');
});

it('returns null as user email for a guest session', function () {
    $session = UserSession::query()->create([
        'id' => 'session-guest-user-email',
        'user_id' => null,
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    expect($session->user_email)->toBeNull();
});

it('returns null as user email when the user does not exist', function () {
    $session = UserSession::query()->create([
        'id' => 'session-ghost-user',
        'user_id' => 99999,
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    expect($session->user_email)->toBeNull();
});

it('casts last_activity into a carbon instance', function () {
    $session = UserSession::query()->create([
        'id' => 'session-last-active',
        'user_id' => 1,
        'payload' => 'test',
        'last_activity' => now()->subMinutes(5)->timestamp,
    ]);

    expect($session->last_active_at)->toBeInstanceOf(Carbon::class)
        ->and($session->last_active_at->format('Y-m-d H:i'))->toBe('2025-12-31 23:55');
});

it('defaults last_active_at to the unix epoch when last_activity is missing', function () {
    $session = new UserSession;

    expect($session->last_active_at->format('U'))->toBe('0');
});

it('flags a session online within the configured threshold', function () {
    config()->set('filament-loginguard.sessions.online_threshold_seconds', 60);

    $online = UserSession::query()->create([
        'id' => 'session-online-flag',
        'user_id' => 1,
        'payload' => 'test',
        'last_activity' => now()->subSeconds(60)->timestamp,
    ]);

    $offline = UserSession::query()->create([
        'id' => 'session-offline-flag',
        'user_id' => 2,
        'payload' => 'test',
        'last_activity' => now()->subSeconds(61)->timestamp,
    ]);

    expect($online->is_online)->toBeTrue()
        ->and($offline->is_online)->toBeFalse();
});

it('honours a custom online threshold', function () {
    config()->set('filament-loginguard.sessions.online_threshold_seconds', 300);

    $session = UserSession::query()->create([
        'id' => 'session-custom-threshold',
        'user_id' => 1,
        'payload' => 'test',
        'last_activity' => now()->subMinutes(4)->timestamp,
    ]);

    expect($session->is_online)->toBeTrue();
});

it('labels online and stale sessions', function () {
    $online = UserSession::query()->create([
        'id' => 'session-label-online',
        'user_id' => 1,
        'payload' => 'test',
        'last_activity' => now()->subSeconds(10)->timestamp,
    ]);

    $stale = UserSession::query()->create([
        'id' => 'session-label-stale',
        'user_id' => 2,
        'payload' => 'test',
        'last_activity' => now()->subMinutes(3)->timestamp,
    ]);

    expect($online->last_active_label)->toBe('Online now')
        ->and($stale->last_active_label)->toBe('3 minutes ago');
});

it('uses the configured sessions table', function () {
    config()->set('filament-loginguard.sessions.table', 'sessions');

    expect((new UserSession)->getTable())->toBe('sessions');

    config()->set('filament-loginguard.sessions.table', 'custom_sessions');

    expect((new UserSession)->getTable())->toBe('custom_sessions');
});

it('returns null as user email when the user model class does not exist', function () {
    config()->set('filament-loginguard.sessions.user_model', 'Not\\A\\Real\\User');

    $session = UserSession::query()->create([
        'id' => 'session-bad-user-model',
        'user_id' => 1,
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    expect($session->user_email)->toBeNull();
});

it('does not flag new-device sessions when new-device tracking is disabled', function () {
    config()->set('filament-loginguard.sessions.new_device.enabled', false);

    KnownDevice::query()->create([
        'user_id' => 42,
        'fingerprint' => 'Chrome on macOS',
        'first_seen_at' => now(),
    ]);

    $session = UserSession::query()->create([
        'id' => 'session-new-device-disabled',
        'user_id' => 42,
        'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    expect($session->is_new_device)->toBeFalse();
});

it('does not flag guest sessions as new devices', function () {
    $session = UserSession::query()->create([
        'id' => 'session-new-device-guest',
        'user_id' => null,
        'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    expect($session->is_new_device)->toBeFalse();
});

it('does not flag sessions as new devices when the user agent cannot be parsed', function () {
    $session = UserSession::query()->create([
        'id' => 'session-new-device-unparseable',
        'user_id' => 42,
        'user_agent' => 'test',
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    expect($session->is_new_device)->toBeFalse();
});
