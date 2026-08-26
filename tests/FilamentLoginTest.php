<?php

use Filament\Auth\Pages\Login;
use Filament\Facades\Filament;
use Filament\Panel;
use Illuminate\Support\Facades\Hash;
use Livewire\Livewire;
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

it('locks out through the native Filament login page', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    UserFactory::new()->create([
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

    expect($row->isLocked())->toBeTrue();

    // A further attempt is rejected by the lockout before any credential work.
    Livewire::test(Login::class)
        ->set('data.email', 'admin@example.com')
        ->set('data.password', 'wrong-password')
        ->call('authenticate')
        ->assertHasErrors(['data.email']);
});
