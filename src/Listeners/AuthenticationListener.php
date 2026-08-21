<?php

namespace SolutionForest\FilamentLoginGuard\Listeners;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use SolutionForest\FilamentLoginGuard\LoginGuardService;

class AuthenticationListener
{
    public function __construct(protected LoginGuardService $service) {}

    /**
     * Pre-check: throw before any credential work so locked keys are rejected fast
     * (Filament runs this inside a Timebox, so the padding still applies).
     */
    public function handleAttempting(Attempting $event): void
    {
        if (! $this->service->isEnabled() || ! $this->shouldTrackGuard($event->guard)) {
            return;
        }

        $ip = (string) request()->ip();
        $email = $this->emailFromCredentials($event->credentials);

        if ($this->service->isWhitelisted($ip, $email)) {
            return;
        }

        if (! $this->service->isLocked($ip, $email)) {
            return;
        }

        throw $this->lockoutException($this->service->remainingLockSeconds($ip, $email));
    }

    /**
     * Record a failure; when this attempt triggers a lockout, notify and surface the lockout message.
     */
    public function handleFailed(Failed $event): void
    {
        if (! $this->service->isEnabled() || ! $this->shouldTrackGuard($event->guard)) {
            return;
        }

        $email = $this->emailFromCredentials($event->credentials);

        if ($email === null) {
            return; // nothing to key on
        }

        $ip = (string) request()->ip();

        if ($this->service->isWhitelisted($ip, $email) || $this->service->isLocked($ip, $email)) {
            return; // never count/extend during an active lock
        }

        $result = $this->service->recordFailure($ip, $email, request()->userAgent());

        if (! $result->locked) {
            return;
        }

        $this->service->notifyLockout($ip, $email, $result->minutes);

        throw $this->lockoutException($result->secondsRemaining);
    }

    /**
     * Successful login: clear counters/locks for this IP and (if known) this email.
     */
    public function handleLogin(Login $event): void
    {
        if (! $this->service->isEnabled() || ! $this->shouldTrackGuard($event->guard)) {
            return;
        }

        $email = null;

        if (method_exists($event->user, 'getAttribute')) {
            $value = $event->user->getAttribute('email');

            if (is_string($value) && filled($value)) {
                $email = Str::lower(trim($value));
            }
        }

        $this->service->resetForSuccess((string) request()->ip(), $email);
    }

    private function emailFromCredentials(array $credentials): ?string
    {
        $email = $credentials['email'] ?? null;

        return is_string($email) && filled($email) ? Str::lower(trim($email)) : null;
    }

    private function shouldTrackGuard(string $guard): bool
    {
        $guards = (array) config('filament-loginguard.tracking.guards', []);

        return $guards === [] || in_array($guard, $guards, true);
    }

    private function lockoutException(int $secondsRemaining): ValidationException
    {
        $minutes = max(1, (int) ceil($secondsRemaining / 60));
        $message = __('filament-loginguard::loginguard.messages.locked', ['minutes' => $minutes]);

        // 'data.email' renders inline in the Filament login form (statePath 'data', same key the
        // core Login page uses); plain 'email' covers non-Filament custom login forms that read
        // standard Laravel validation errors. The extra key is inert in Livewire if unmatched.
        return ValidationException::withMessages([
            'data.email' => $message,
            'email' => $message,
        ]);
    }
}
