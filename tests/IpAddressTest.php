<?php

use SolutionForest\FilamentLoginGuard\LoginGuardService;
use SolutionForest\FilamentLoginGuard\Models\LockoutHistory;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Models\LoginGuardLock;
use SolutionForest\FilamentLoginGuard\Support\IpAddress;

it('returns an empty string for null and blank input', function (?string $input) {
    expect(IpAddress::normalize($input))->toBe('');
})->with([
    [null],
    [''],
    ['   '],
]);

it('reduces an IPv4-mapped IPv6 address to plain IPv4', function (string $ip) {
    expect(IpAddress::normalize($ip))->toBe('1.2.3.4');
})->with([
    'dotted' => '::ffff:1.2.3.4',
    'uppercase' => '::FFFF:1.2.3.4',
    'hexadecimal' => '0:0:0:0:0:FFFF:0102:0304',
]);

it('canonicalizes IPv6 representation', function (string $input, string $expected) {
    expect(IpAddress::normalize($input))->toBe($expected);
})->with([
    ['2001:0DB8:0000::0001', '2001:db8::1'],
    ['2001:DB8::1', '2001:db8::1'],
    ['2001:0:0:1:0:0:0:1', '2001:0:0:1::1'],
]);

it('leaves a plain IPv4 address unchanged', function () {
    expect(IpAddress::normalize('1.2.3.4'))->toBe('1.2.3.4');
});

it('returns unrecognized strings unchanged', function () {
    expect(IpAddress::normalize('not-an-ip'))->toBe('not-an-ip');
});

it('uses the request ip when no trusted proxies are configured', function () {
    request()->server->set('REMOTE_ADDR', '1.2.3.4');
    request()->headers->set('X-Forwarded-For', '9.9.9.9');

    expect(IpAddress::fromRequest())->toBe('1.2.3.4');
});

it('resolves the real client ip behind a trusted proxy', function () {
    config()->set('filament-loginguard.lockout.trusted_proxies', ['10.0.0.1']);

    request()->server->set('REMOTE_ADDR', '10.0.0.1');
    request()->headers->set('X-Forwarded-For', '203.0.113.7, 10.0.0.1');

    expect(IpAddress::fromRequest())->toBe('203.0.113.7');
});

it('walks the x-forwarded-for chain past multiple trusted proxies', function () {
    config()->set('filament-loginguard.lockout.trusted_proxies', ['10.0.0.1', '10.0.0.2']);

    request()->server->set('REMOTE_ADDR', '10.0.0.1');
    request()->headers->set('X-Forwarded-For', '203.0.113.7, 10.0.0.2, 10.0.0.1');

    expect(IpAddress::fromRequest())->toBe('203.0.113.7');
});

it('ignores client-appended entries in the forwarded chain', function () {
    config()->set('filament-loginguard.lockout.trusted_proxies', ['10.0.0.1']);

    // The client sent its own fake "X-Forwarded-For: 6.6.6.6"; the proxy appended
    // the real client IP. Walking right-to-left, 1.2.3.4 is the first untrusted entry.
    request()->server->set('REMOTE_ADDR', '10.0.0.1');
    request()->headers->set('X-Forwarded-For', '6.6.6.6, 1.2.3.4');

    expect(IpAddress::fromRequest())->toBe('1.2.3.4');
});

it('falls back to the proxy ip when the whole forwarded chain is trusted', function () {
    config()->set('filament-loginguard.lockout.trusted_proxies', ['10.0.0.0/8']);

    request()->server->set('REMOTE_ADDR', '10.0.0.1');
    request()->headers->set('X-Forwarded-For', '10.0.0.2, 10.0.0.3');

    expect(IpAddress::fromRequest())->toBe('10.0.0.1');
});

it('matches trusted proxies by cidr range', function () {
    config()->set('filament-loginguard.lockout.trusted_proxies', ['10.0.0.0/8']);

    request()->server->set('REMOTE_ADDR', '10.1.2.3');
    request()->headers->set('X-Forwarded-For', '203.0.113.7');

    expect(IpAddress::fromRequest())->toBe('203.0.113.7');
});

it('uses the proxy ip when it is not listed as trusted', function () {
    config()->set('filament-loginguard.lockout.trusted_proxies', ['10.0.0.1']);

    request()->server->set('REMOTE_ADDR', '11.1.1.1');
    request()->headers->set('X-Forwarded-For', '203.0.113.7');

    expect(IpAddress::fromRequest())->toBe('11.1.1.1');
});

it('normalizes a forwarded ipv4-mapped ipv6 client address', function () {
    config()->set('filament-loginguard.lockout.trusted_proxies', ['10.0.0.1']);

    request()->server->set('REMOTE_ADDR', '10.0.0.1');
    request()->headers->set('X-Forwarded-For', '::ffff:203.0.113.7');

    expect(IpAddress::fromRequest())->toBe('203.0.113.7');
});

it('honors a mapped IPv4 lock created before canonicalization', function (string $scope, string $suffix) {
    $service = app(LoginGuardService::class);
    $until = now()->addHour()->startOfSecond();
    LoginGuardLock::query()->create([
        'scope_type' => $scope, 'scope_key' => '::ffff:192.0.2.1' . $suffix,
        'locked_until' => $until, 'escalation_count' => 1,
    ]);

    expect($service->lockFor('192.0.2.1', 'owner@example.test')?->equalTo($until))->toBeTrue()
        ->and($service->isLocked('192.0.2.2', 'owner@example.test'))->toBeFalse()
        ->and($service->isLocked('192.0.2.1', 'other@example.test'))->toBe($scope === 'ip');

    $service->releaseLocksForPair('192.0.2.1', 'owner@example.test');
    expect(LoginGuardLock::query()->count())->toBe(0);
})->with([['ip', ''], ['pair', '|owner@example.test']]);

it('counts historical IPv4 attempts in the active window and retains escalation', function (bool $perIp) {
    config()->set('filament-loginguard.lockout.tracking.per_ip', $perIp);
    config()->set('filament-loginguard.lockout.tracking.per_email', false);
    config()->set('filament-loginguard.lockout.max_attempts', 4);
    $email = 'owner@example.test';
    $legacy = '::ffff:192.0.2.1';
    LoginAttempt::factory()->create([
        'ip' => $legacy, 'email' => $perIp ? 'historical@example.test' : $email,
        'attempts' => 2, 'window_started_at' => now()->subMinute(),
    ]);
    LockoutHistory::query()->create([
        'ip' => $legacy, 'email' => $perIp ? null : $email,
        'locked_at' => now()->subDays(4), 'locked_until' => now()->subDays(3),
        'duration_minutes' => 1440, 'lockout_count' => 2,
    ]);

    $service = app(LoginGuardService::class);
    expect($service->recordFailure('192.0.2.1', $email)->locked)->toBeFalse();
    $result = $service->recordFailure('192.0.2.1', $email);
    expect($result->locked)->toBeTrue()
        ->and($result->minutes)->toBe(72 * 60)
        ->and(LoginGuardLock::query()->sole()->scope_key)->toBe($perIp ? '192.0.2.1' : '192.0.2.1|' . $email)
        ->and(LockoutHistory::query()->where('ip', $legacy)->count())->toBe(1);
})->with([true, false]);

it('clears both IPv4 spellings on successful authentication', function () {
    $email = 'owner@example.test';
    foreach (['::ffff:192.0.2.1', '192.0.2.1', '192.0.2.2'] as $ip) {
        LoginAttempt::factory()->create(['ip' => $ip, 'email' => $email, 'attempts' => 2, 'window_started_at' => now()]);
    }

    app(LoginGuardService::class)->recordSuccess('192.0.2.1', $email);
    expect(LoginAttempt::query()->where('ip', '!=', '192.0.2.2')->sum('attempts'))->toEqual(0)
        ->and(LoginAttempt::query()->where('ip', '192.0.2.2')->sole()->attempts)->toBe(2);
});

it('preserves a longer existing mapped lock and releases the same logical scope', function (string $scope) {
    config()->set('filament-loginguard.lockout.tracking.per_ip', $scope === 'ip');
    config()->set('filament-loginguard.lockout.tracking.per_email', false);
    config()->set('filament-loginguard.lockout.max_attempts', 1);
    $suffix = $scope === 'pair' ? '|owner@example.test' : '';
    LoginGuardLock::query()->create(['scope_type' => $scope, 'scope_key' => '::ffff:192.0.2.1' . $suffix, 'locked_until' => now()->addDay()]);
    $service = app(LoginGuardService::class);

    expect($service->recordFailure('192.0.2.1', 'owner@example.test')->locked)->toBeFalse()
        ->and(LoginGuardLock::query()->count())->toBe(1)
        ->and($service->releaseLock($scope, '192.0.2.1' . $suffix))->toBe(1)
        ->and($service->isLocked('192.0.2.1', 'owner@example.test'))->toBeFalse();
})->with(['ip', 'pair']);
