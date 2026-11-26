<?php

use Filament\Auth\Pages\Login;
use Filament\Facades\Filament;
use Filament\Panel;
use Illuminate\Support\Facades\Hash;
use Livewire\Livewire;
use SolutionForest\FilamentLoginGuard\LoginGuardService;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;

beforeEach(function () {
    config()->set('auth.providers.users.model', User::class);
    config()->set('filament-loginguard.lockout.whitelist.ips', []);
    config()->set('filament-loginguard.lockout.notifications.enabled', false);

    $panel = Panel::make()
        ->id('admin')
        ->default()
        ->login();

    Filament::registerPanel($panel);
    Filament::setCurrentPanel($panel);
});

it('records a failed attempt through the native Filament login page', function () {
    UserFactory::new()->create([
        'email' => 'admin@example.com',
        'password' => Hash::make('secret'),
    ]);

    Livewire::test(Login::class)
        ->set('data.email', 'admin@example.com')
        ->set('data.password', 'wrong-password')
        ->call('authenticate')
        ->assertHasErrors(['data.email']);

    $row = LoginAttempt::query()->where('email', 'admin@example.com')->sole();

    expect($row->attempts)->toBe(1);
});

it('rejects the correct password until the native Filament login lock expires', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    $user = UserFactory::new()->create([
        'email' => 'admin@example.com',
        'password' => Hash::make('secret'),
    ]);

    foreach (range(1, 2) as $attempt) {
        Livewire::test(Login::class)
            ->set('data.email', 'admin@example.com')
            ->set('data.password', 'wrong-password')
            ->call('authenticate')
            ->assertHasErrors(['data.email']);
    }

    $row = LoginAttempt::query()->where('email', 'admin@example.com')->sole();

    $service = app(LoginGuardService::class);
    $lockedUntil = $service->lockFor($row->ip, $row->email);

    expect($lockedUntil)->not->toBeNull();

    Livewire::test(Login::class)
        ->set('data.email', 'admin@example.com')
        ->set('data.password', 'secret')
        ->call('authenticate')
        ->assertHasErrors(['data.email']);

    $this->assertGuest();
    expect($row->refresh()->attempts)->toBe(2)
        ->and($row->success_count)->toBe(0)
        ->and($service->lockFor($row->ip, $row->email)?->equalTo($lockedUntil))->toBeTrue();

    $this->travelTo($lockedUntil, function () use ($user, $row): void {
        Livewire::test(Login::class)
            ->set('data.email', 'admin@example.com')
            ->set('data.password', 'secret')
            ->call('authenticate')
            ->assertHasNoErrors();

        $this->assertAuthenticatedAs($user);
        expect($row->refresh()->attempts)->toBe(0)
            ->and($row->success_count)->toBe(1);
    });
});
