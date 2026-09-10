<?php

use SolutionForest\FilamentLoginGuard\Support\ParsesUserAgent;

it('parses a browser and os into a fingerprint', function () {
    expect(ParsesUserAgent::parseDeviceName('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'))
        ->toBe('Edge on Windows');
});

it('parses an os only when there is no browser', function () {
    expect(ParsesUserAgent::parseDeviceName('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'))
        ->toBe('macOS');
});

it('parses a browser only when there is no os', function () {
    expect(ParsesUserAgent::parseDeviceName('Googlebot/2.1 (+http://www.google.com/bot.html)'))
        ->toBe('Googlebot');
});

it('returns null for a null user agent', function () {
    expect(ParsesUserAgent::parseDeviceName(null))->toBeNull();
});

it('returns null for an empty user agent', function () {
    expect(ParsesUserAgent::parseDeviceName(''))->toBeNull();
});

it('returns null when nothing meaningful can be extracted', function () {
    expect(ParsesUserAgent::parseDeviceName('test'))->toBeNull();
});
