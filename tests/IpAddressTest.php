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
