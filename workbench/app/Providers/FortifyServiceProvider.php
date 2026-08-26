<?php

namespace Workbench\App\Providers;

use Illuminate\Support\ServiceProvider;
use Laravel\Fortify\Features;
use Laravel\Fortify\Fortify;
use Workbench\App\Actions\Fortify\CreateNewUser;
use Workbench\App\Actions\Fortify\ResetUserPassword;
use Workbench\App\Models\User;

class FortifyServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        config()->set('auth.providers.users.model', User::class);
        config()->set('fortify.home', '/dashboard');
        config()->set('fortify.features', [
            Features::registration(),
            Features::resetPasswords(),
        ]);

        // For manual browser testing on localhost, drop the localhost whitelist
        // and lower the threshold so lockouts are quick to trigger. Tests keep
        // the package defaults and configure their own values per-test.
        if (! $this->app->runningUnitTests()) {
            config()->set('filament-loginguard.lockout.whitelist.ips', []);
            config()->set('filament-loginguard.lockout.max_attempts', 3);
        }
    }

    public function boot(): void
    {
        Fortify::createUsersUsing(CreateNewUser::class);
        Fortify::resetUserPasswordsUsing(ResetUserPassword::class);

        Fortify::loginView(fn () => view('auth.login'));
        Fortify::registerView(fn () => view('auth.register'));
        Fortify::requestPasswordResetLinkView(fn () => view('auth.forgot-password'));
        Fortify::resetPasswordView(fn () => view('auth.reset-password'));
    }
}
