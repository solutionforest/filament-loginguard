<?php

use Livewire\Livewire;
use SolutionForest\FilamentLoginGuard\LoginGuardService;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Tests\Support\TestLivewireComponent;

it('asserts the failed attempts count for an email', function () {
    LoginAttempt::factory()->create(['email' => 'a@example.com', 'attempts' => 3]);
    LoginAttempt::factory()->create(['email' => 'b@example.com', 'attempts' => 5]);

    Livewire::test(TestLivewireComponent::class)
        ->assertLoginGuardAttempts(3, 'a@example.com')
        ->assertLoginGuardAttempts(5, 'b@example.com');
});

it('asserts an email is locked out', function () {
    LoginAttempt::factory()->locked(ip: '1.2.3.4', email: 'a@example.com', lockedUntil: now()->addMinutes(15))->create();
    LoginAttempt::factory()->create(['email' => 'b@example.com', 'attempts' => 2]);

    Livewire::test(TestLivewireComponent::class)
        ->assertLoginGuardLocked('a@example.com')
        ->assertLoginGuardNotLocked('b@example.com');
});

it('scopes assertions to an ip when provided', function () {
    LoginAttempt::factory()->create([
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'attempts' => 2,
    ]);
    LoginAttempt::factory()->create([
        'ip' => '5.6.7.8',
        'email' => 'a@example.com',
        'attempts' => 9,
    ]);

    Livewire::test(TestLivewireComponent::class)
        ->assertLoginGuardAttempts(2, 'a@example.com', '1.2.3.4')
        ->assertLoginGuardAttempts(11, 'a@example.com');
});

it('detects a pair lock only for the matching email and ip', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 1);
    config()->set('filament-loginguard.lockout.tracking.per_ip', false);
    config()->set('filament-loginguard.lockout.tracking.per_email', false);

    app(LoginGuardService::class)->recordFailure('1.2.3.4', 'a@example.com');

    Livewire::test(TestLivewireComponent::class)
        ->assertLoginGuardLocked('a@example.com', '1.2.3.4')
        ->assertLoginGuardNotLocked('a@example.com', '5.6.7.8')
        ->assertLoginGuardNotLocked('b@example.com', '1.2.3.4')
        ->assertLoginGuardNotLocked('a@example.com');
});
