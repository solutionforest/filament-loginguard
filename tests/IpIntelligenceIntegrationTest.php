<?php

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Validation\ValidationException;
use SolutionForest\FilamentLoginGuard\IpLocation;
use SolutionForest\FilamentLoginGuard\Models\LocationHistory;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;
use SolutionForest\FilamentLoginGuard\Services\IpIntelligence;
use SolutionForest\FilamentLoginGuard\Tests\Support\TestUser;

beforeEach(function () {
    request()->server->set('REMOTE_ADDR', '1.2.3.4');
    config()->set('filament-loginguard.lockout.whitelist.ips', []);

    $this->location = new IpLocation(
        country: 'US',
        countryName: 'United States',
        city: 'Minneapolis',
        subdivision: 'Minnesota',
        latitude: 44.9733,
        longitude: -93.2323,
        accuracyRadiusKm: 20,
        asn: 7922,
        asnOrganization: 'Comcast',
    );

    // Swap the container binding for a deterministic fake so the listener
    // exercises the full enrichment path without a real .mmdb file.
    $this->bindFake = function (?IpLocation $location): void {
        app()->instance(IpIntelligence::class, new class($location) implements IpIntelligence
        {
            public function __construct(private ?IpLocation $location) {}

            public function lookup(string $ip): ?IpLocation
            {
                return $this->location;
            }
        });
    };
});

it('records location signals and flags a first-seen location on a successful login', function () {
    ($this->bindFake)($this->location);

    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    $event = SecurityEvent::query()->where('type', SecurityEvent::TYPE_LOGIN_SUCCEEDED)->sole();

    expect($event->metadata['country'])->toBe('US')
        ->and($event->metadata['country_name'])->toBe('United States')
        ->and($event->metadata['city'])->toBe('Minneapolis')
        ->and($event->metadata['asn'])->toBe(7922)
        ->and($event->metadata['is_new_country'])->toBeTrue()
        ->and($event->metadata['is_new_asn'])->toBeTrue();

    $row = LocationHistory::query()->sole();

    expect($row->country)->toBe('US')
        ->and($row->asn)->toBe(7922)
        ->and($row->guard)->toBe('web')
        ->and($row->user_type)->toBe(TestUser::class)
        ->and($row->user_identifier)->toBe('1');
});

it('records location signals on a failed login', function () {
    ($this->bindFake)($this->location);

    try {
        event(new Failed('web', null, ['email' => 'a@example.com', 'password' => 'x']));
    } catch (ValidationException) {
        // Expected when the attempt crosses the lockout threshold.
    }

    $event = SecurityEvent::query()->where('type', SecurityEvent::TYPE_LOGIN_FAILED)->sole();

    expect($event->metadata['country'])->toBe('US')
        ->and($event->metadata['asn'])->toBe(7922);
});

it('flags a repeat location as not new', function () {
    LocationHistory::record('web', TestUser::class, '1', 'US', 7922);

    ($this->bindFake)($this->location);

    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    $event = SecurityEvent::query()->where('type', SecurityEvent::TYPE_LOGIN_SUCCEEDED)->sole();

    expect($event->metadata['is_new_country'])->toBeFalse()
        ->and($event->metadata['is_new_asn'])->toBeFalse();
});

it('records no location metadata when the lookup returns null', function () {
    // The default MaxmindIpIntelligence is disabled, so lookup() returns null.
    event(new Login('web', new TestUser(email: 'a@example.com'), false));

    $event = SecurityEvent::query()->where('type', SecurityEvent::TYPE_LOGIN_SUCCEEDED)->sole();

    expect($event->metadata)->toBeNull()
        ->and(LocationHistory::query()->count())->toBe(0);
});
