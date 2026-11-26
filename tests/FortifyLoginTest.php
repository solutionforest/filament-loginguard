<?php

use Illuminate\Support\Facades\Hash;
use SolutionForest\FilamentLoginGuard\LoginGuardService;
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

it('rejects the correct password until the native Fortify login lock expires', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    $user = UserFactory::new()->create([
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

    $service = app(LoginGuardService::class);
    $lockedUntil = $service->lockFor($row->ip, $row->email);

    expect($lockedUntil)->not->toBeNull();

    $this->post('/login', [
        'email' => 'admin@example.com',
        'password' => 'secret',
    ])->assertSessionHasErrors('email');

    $this->assertGuest();
    expect($row->refresh()->attempts)->toBe(2)
        ->and($row->success_count)->toBe(0)
        ->and($service->lockFor($row->ip, $row->email)?->equalTo($lockedUntil))->toBeTrue();

    $this->travelTo($lockedUntil, function () use ($user, $row): void {
        $this->post('/login', [
            'email' => 'admin@example.com',
            'password' => 'secret',
        ])->assertRedirect('/dashboard')->assertSessionHasNoErrors();

        $this->assertAuthenticatedAs($user);
        expect($row->refresh()->attempts)->toBe(0)
            ->and($row->success_count)->toBe(1);
    });
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
