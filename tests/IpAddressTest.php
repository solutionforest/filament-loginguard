<?php

use SolutionForest\FilamentLoginGuard\Support\IpAddress;

it('returns an empty string for null and blank input', function (?string $input) {
    expect(IpAddress::normalize($input))->toBe('');
})->with([
    [null],
    [''],
    ['   '],
]);

it('reduces an IPv4-mapped IPv6 address to plain IPv4', function () {
    expect(IpAddress::normalize('::ffff:1.2.3.4'))->toBe('1.2.3.4');
});

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
