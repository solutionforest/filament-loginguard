<?php

use Illuminate\Support\Facades\Hash;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use Workbench\Database\Factories\UserFactory;

beforeEach(function () {
    config()->set('filament-loginguard.lockout.whitelist.ips', []);
    config()->set('filament-loginguard.lockout.notifications.enabled', false);
});

it('records a failed attempt through the native Fortify login', function () {
    UserFactory::new()->create([
        'email' => 'admin@example.com',
        'password' => Hash::make('secret'),
    ]);

    $this->post('/login', [
        'email' => 'admin@example.com',
        'password' => 'wrong-password',
    ])->assertSessionHasErrors('email');

    $row = LoginAttempt::query()->where('email', 'admin@example.com')->sole();

    expect($row->attempts)->toBe(1);
});

it('locks out through the native Fortify login', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    UserFactory::new()->create([
        'email' => 'admin@example.com',
        'password' => Hash::make('secret'),
    ]);

    foreach (range(1, 2) as $attempt) {
        $this->post('/login', [
            'email' => 'admin@example.com',
            'password' => 'wrong-password',
        ])->assertSessionHasErrors('email');
    }

    $row = LoginAttempt::query()->where('email', 'admin@example.com')->sole();

    expect($row->isLocked())->toBeTrue();

    // A further attempt is rejected by the lockout before any credential work.
    $this->post('/login', [
        'email' => 'admin@example.com',
        'password' => 'wrong-password',
    ])->assertSessionHasErrors('email');
});

it('resets the counter after a successful Fortify login', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 5);

    UserFactory::new()->create([
        'email' => 'admin@example.com',
        'password' => Hash::make('secret'),
    ]);

    $this->post('/login', [
        'email' => 'admin@example.com',
        'password' => 'wrong-password',
    ])->assertSessionHasErrors('email');

    $this->post('/login', [
        'email' => 'admin@example.com',
        'password' => 'secret',
    ])->assertRedirect('/dashboard');

    $row = LoginAttempt::query()->where('email', 'admin@example.com')->sole();

    expect($row->attempts)->toBe(0)
        ->and($row->success_count)->toBe(1);
});
