<?php

namespace SolutionForest\FilamentLoginGuard\Tests\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Gate;

class TestUser implements Authenticatable
{
    public function __construct(
        public int $id = 1,
        public ?string $email = 'admin@example.com',
    ) {}

    public function can(string $ability, mixed $arguments = []): bool
    {
        return Gate::forUser($this)->check($ability, $arguments);
    }

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    public function getAuthIdentifier(): int
    {
        return $this->id;
    }

    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    public function getAuthPassword(): ?string
    {
        return null;
    }

    public function getRememberToken(): ?string
    {
        return null;
    }

    public function setRememberToken($value): void {}

    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }

    public function getAttribute(string $key): mixed
    {
        return $this->{$key} ?? null;
    }
}
