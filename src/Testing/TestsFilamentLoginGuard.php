<?php

namespace SolutionForest\FilamentLoginGuard\Testing;

use Closure;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Testing\Assert;
use Livewire\Features\SupportTesting\Testable;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;

/**
 * @mixin Testable
 */
class TestsFilamentLoginGuard
{
    public function assertLoginGuardAttempts(): Closure
    {
        return function (int $expected, string $email, ?string $ip = null): static {
            $attempts = (int) LoginAttempt::query()
                ->where('email', $email)
                ->when($ip !== null, fn (Builder $query): Builder => $query->where('ip', $ip))
                ->sum('attempts');

            Assert::assertSame(
                $expected,
                $attempts,
                "Expected [{$email}] to have {$expected} failed login attempts, found {$attempts}."
            );

            return $this;
        };
    }

    public function assertLoginGuardLocked(): Closure
    {
        return function (string $email, ?string $ip = null): static {
            $locked = LoginAttempt::query()
                ->where('email', $email)
                ->when($ip !== null, fn (Builder $query): Builder => $query->where('ip', $ip))
                ->where('locked_until', '>', now())
                ->exists();

            Assert::assertTrue(
                $locked,
                "Expected [{$email}] to be locked out by the login guard, but it was not."
            );

            return $this;
        };
    }

    public function assertLoginGuardNotLocked(): Closure
    {
        return function (string $email, ?string $ip = null): static {
            $locked = LoginAttempt::query()
                ->where('email', $email)
                ->when($ip !== null, fn (Builder $query): Builder => $query->where('ip', $ip))
                ->where('locked_until', '>', now())
                ->exists();

            Assert::assertFalse(
                $locked,
                "Expected [{$email}] not to be locked out by the login guard, but it was."
            );

            return $this;
        };
    }
}
