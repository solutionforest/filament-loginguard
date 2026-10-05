<?php

namespace SolutionForest\FilamentLoginGuard\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Carbon;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Models\LoginGuardLock;

class LoginAttemptFactory extends Factory
{
    protected $model = LoginAttempt::class;

    public function definition(): array
    {
        return [
            'ip' => fake()->ipv4(),
            'email' => fake()->safeEmail(),
            'attempts' => 0,
            'lockout_count' => 0,
            'locked_until' => null,
            'last_attempt_at' => now(),
        ];
    }

    /**
     * Create a locked attempt row plus the scoped lock(s) the new lock-state
     * model requires. `lockedUntil` may be null for a released-but-recorded
     * lock (kept for rows that were unblocked by an admin).
     */
    public function locked(?string $ip = null, ?string $email = null, ?Carbon $lockedUntil = null): static
    {
        return $this->state(function () use ($ip, $email, $lockedUntil): array {
            $attributes = [
                'attempts' => (int) config('filament-loginguard.lockout.max_attempts'),
                'lockout_count' => 1,
            ];

            if ($ip !== null) {
                $attributes['ip'] = $ip;
            }

            if ($email !== null) {
                $attributes['email'] = $email;
            }

            // Create the matching scoped locks so the security state actually
            // blocks the row. The per-row locked_until column is legacy-only.
            if ($lockedUntil !== null) {
                $attributes['ip'] ??= fake()->ipv4();
                $attributes['email'] ??= fake()->safeEmail();

                LoginGuardLock::query()->updateOrCreate(
                    ['scope_type' => LoginGuardLock::SCOPE_IP, 'scope_key' => $attributes['ip']],
                    ['locked_until' => $lockedUntil, 'escalation_count' => 1],
                );
                LoginGuardLock::query()->updateOrCreate(
                    ['scope_type' => LoginGuardLock::SCOPE_EMAIL, 'scope_key' => $attributes['email']],
                    ['locked_until' => $lockedUntil, 'escalation_count' => 1],
                );
            }

            return $attributes;
        });
    }
}
