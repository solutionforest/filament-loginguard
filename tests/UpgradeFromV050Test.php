<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SolutionForest\FilamentLoginGuard\LoginGuardService;
use SolutionForest\FilamentLoginGuard\Models\LockoutHistory;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Models\LoginGuardLock;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;

/**
 * Reproduces the v0.5.0 → v0.6.1 upgrade path: the v0.5 schema is created
 * manually (NOT NULL history columns, no locks/events tables, legacy attempt
 * locks), the released migrations are marked as already run, and the v0.6.1
 * migrations are then applied. Everything after that must work without SQL
 * errors — this is the path real production databases take.
 */
beforeEach(function () {
    // Config can leak between tests in this file; reset the toggles the
    // non-upgrade tests override.
    config()->set('filament-loginguard.lockout.whitelist.ips', []);
    config()->set('filament-loginguard.lockout.tracking.per_ip', true);
    config()->set('filament-loginguard.lockout.tracking.per_email', true);
});

it('upgrades cleanly from a v0.5 schema', function () {
    // LazilyRefreshDatabase only migrates on the first query — force it now,
    // BEFORE the v0.5 schema below replaces the package tables, otherwise the
    // deferred migrate would wipe them mid-test.
    DB::select('select 1');
    Schema::dropIfExists('migrations');
    Schema::create('migrations', function (Blueprint $table): void {
        $table->increments('id');
        $table->string('migration');
        $table->integer('batch');
    });

    // ── Build the v0.5.0 schema exactly as v0.5.0 shipped it. ──
    Schema::dropIfExists('filament_loginguard_lockout_histories');
    Schema::dropIfExists('filament_loginguard_locks');
    Schema::dropIfExists('filament_loginguard_events');
    Schema::dropIfExists('filament_loginguard_attempts');

    Schema::create('filament_loginguard_attempts', function (Blueprint $table): void {
        $table->id();
        $table->string('ip', 45);
        $table->string('email');
        $table->string('user_agent')->nullable();
        $table->unsignedInteger('attempts')->default(0);
        $table->unsignedInteger('lockout_count')->default(0);
        $table->unsignedInteger('success_count')->default(0);
        $table->timestamp('locked_until')->nullable();
        $table->timestamp('last_attempt_at')->nullable();
        $table->timestamp('last_success_at')->nullable();
        $table->timestamp('window_started_at')->nullable();
        $table->timestamps();
        $table->unique(['ip', 'email']);
    });

    // Note: ip and email are NOT NULL — this is the crux of the regression.
    Schema::create('filament_loginguard_lockout_histories', function (Blueprint $table): void {
        $table->id();
        $table->string('ip', 45);
        $table->string('email');
        $table->timestamp('locked_at');
        $table->timestamp('locked_until');
        $table->unsignedInteger('lockout_count');
        $table->unsignedInteger('duration_minutes');
        $table->string('triggered_by_ip', 45)->nullable();
        $table->string('triggered_by_email')->nullable();
        $table->timestamps();
        $table->index(['ip', 'email']);
    });

    // A v0.5-era active lock and an escalation history at the 3rd step.
    DB::table('filament_loginguard_attempts')->insert([
        'ip' => '203.0.113.9',
        'email' => 'victim@example.com',
        'attempts' => 10,
        'lockout_count' => 3,
        'locked_until' => now()->addMinutes(10),
        'last_attempt_at' => now(),
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    DB::table('filament_loginguard_lockout_histories')->insert([
        ['ip' => '203.0.113.9', 'email' => 'victim@example.com', 'locked_at' => now()->subDays(3), 'locked_until' => now()->subDays(3)->addMinutes(15), 'lockout_count' => 1, 'duration_minutes' => 15, 'created_at' => now(), 'updated_at' => now()],
        ['ip' => '203.0.113.9', 'email' => 'victim@example.com', 'locked_at' => now()->subDays(2), 'locked_until' => now()->subDays(2)->addHours(24), 'lockout_count' => 2, 'duration_minutes' => 1440, 'created_at' => now(), 'updated_at' => now()],
        ['ip' => '203.0.113.9', 'email' => 'victim@example.com', 'locked_at' => now()->subDay(), 'locked_until' => now()->subDay()->addHours(72), 'lockout_count' => 3, 'duration_minutes' => 4320, 'created_at' => now(), 'updated_at' => now()],
    ]);

    // ── Mark the released v0.5/v0.6.0 migrations as already run. The v0.6.0
    // locks/events tables were created by the v0.6.0 install; recreate them in
    // their v0.6.0 shape (scope_key 191, before the widening migration). ──
    Schema::create('filament_loginguard_locks', function (Blueprint $table): void {
        $table->id();
        $table->string('scope_type');
        $table->string('scope_key', 191);
        $table->timestamp('locked_until');
        $table->unsignedInteger('escalation_count')->default(0);
        $table->timestamps();
        $table->unique(['scope_type', 'scope_key']);
        $table->index('locked_until');
    });

    Schema::create('filament_loginguard_events', function (Blueprint $table): void {
        $table->id();
        $table->string('type')->index();
        $table->string('ip', 45)->nullable()->index();
        $table->string('email')->nullable()->index();
        $table->unsignedBigInteger('user_id')->nullable();
        $table->string('guard')->nullable();
        $table->string('device')->nullable();
        $table->timestamp('occurred_at')->index();
        $table->json('metadata')->nullable();
        $table->timestamps();
    });

    $released = [
        'create_filament_loginguard_locks_table',
        'create_filament_loginguard_events_table',
        'update_filament_loginguard_upgrade_to_scoped_locks' => false, // runs below
    ];

    foreach ([
        'create_filament_loginguard_locks_table',
        'create_filament_loginguard_events_table',
    ] as $migration) {
        DB::table('migrations')->insert(['migration' => $migration, 'batch' => 1]);
    }

    // The testbench migrator already ran every package migration during setUp
    // (including the v0.6.1 one), so artisan migrate reports "nothing to
    // migrate". Invoke the upgrade migration's up() directly — exactly what
    // `php artisan migrate` would do on a real v0.5 database.
    $upgradeMigration = require __DIR__ . '/../database/migrations/update_filament_loginguard_upgrade_to_scoped_locks.php';
    $upgradeMigration->up();

    // ── The v0.5 → v0.6.1 assertions. ──

    // P0: scoped history inserts no longer violate the NOT NULL constraints.
    config()->set('filament-loginguard.lockout.whitelist.ips', []);
    config()->set('filament-loginguard.lockout.max_attempts', 2);
    $service = app(LoginGuardService::class);

    expect($service->isLocked('203.0.113.9', 'victim@example.com'))->toBeTrue('the backfilled lock keeps blocking');

    // The backfill restored the legacy lock into BOTH scopes.
    expect(LoginGuardLock::query()->where('scope_type', 'ip')->where('scope_key', '203.0.113.9')->exists())->toBeTrue()
        ->and(LoginGuardLock::query()->where('scope_type', 'email')->where('scope_key', 'victim@example.com')->exists())->toBeTrue();

    // Release the backfilled IP lock and trigger a fresh lockout: the scoped
    // insert (email = NULL) must not fail, and the v0.5 escalation history
    // (lockout_count = 3) must put the next lock at the 4th step (7 days).
    $service->releaseLock('ip', '203.0.113.9', reason: 'admin_unblock');
    $service->releaseLock('email', 'victim@example.com', reason: 'admin_unblock');

    expect($service->isLocked('203.0.113.9', 'victim@example.com'))->toBeFalse();

    $service->recordFailure('203.0.113.9', 'victim@example.com');
    $result = $service->recordFailure('203.0.113.9', 'victim@example.com');

    expect($result->locked)->toBeTrue()
        ->and($result->minutes)->toBe(7 * 24 * 60);

    // The scoped history insert has exactly one column filled.
    $ipScoped = LockoutHistory::query()->whereNull('email')->where('ip', '203.0.113.9')->sole();
    $emailScoped = LockoutHistory::query()->whereNull('ip')->where('email', 'victim@example.com')->sole();

    expect($ipScoped->lockout_count)->toBe(4)
        ->and($emailScoped->lockout_count)->toBe(4);

    // The unlock events were recorded with their reasons.
    $unlocked = SecurityEvent::query()->where('type', SecurityEvent::TYPE_UNLOCKED)->get();

    expect($unlocked)->toHaveCount(2)
        ->and($unlocked->pluck('metadata.reason')->unique()->values()->all())->toBe(['admin_unblock']);
});

it('never shortens a stronger v0.6 scoped lock during the backfill', function () {
    // v0.6.0 → v0.6.1: a real scoped lock already exists (24h, escalated
    // twice) AND a legacy attempt row still carries a shorter lock. The
    // backfill must keep the stronger state.
    $legacyExpiry = now()->addMinutes(10)->startOfSecond();
    $scopedExpiry = now()->addDay()->startOfSecond();

    DB::table('filament_loginguard_attempts')->insert([
        'email' => 'upgraded@example.com',
        'attempts' => 10,
        'lockout_count' => 2,
        'locked_until' => $legacyExpiry, // legacy: expires in 10 minutes
        'last_attempt_at' => now(),
        'created_at' => now(),
        'updated_at' => now(),
        'ip' => '198.51.100.7',
    ]);

    LoginGuardLock::query()->create([
        'scope_type' => 'ip',
        'scope_key' => '198.51.100.7',
        'locked_until' => $scopedExpiry, // v0.6 scoped: expires in 24 hours
        'escalation_count' => 2,
    ]);

    $upgrade = require __DIR__ . '/../database/migrations/update_filament_loginguard_upgrade_to_scoped_locks.php';
    $upgrade->up();

    $ipLock = LoginGuardLock::query()->where('scope_type', 'ip')->where('scope_key', '198.51.100.7')->sole();

    // locked_until kept the LONGER of the two; escalation kept the HIGHER.
    expect($ipLock->locked_until->equalTo($scopedExpiry))->toBeTrue()
        ->and($ipLock->escalation_count)->toBe(2)
        ->and(app(LoginGuardService::class)->isLocked('198.51.100.7', 'upgraded@example.com'))->toBeTrue();

    // The email scope had no v0.6 lock, so it gets the legacy state seeded.
    $emailLock = LoginGuardLock::query()->where('scope_type', 'email')->where('scope_key', 'upgraded@example.com')->sole();

    expect($emailLock->locked_until->equalTo($legacyExpiry))->toBeTrue();
});

it('releases pair locks when an admin unblocks and accounts for them in filter and cleanup', function () {
    config()->set('filament-loginguard.lockout.tracking.per_ip', false);
    config()->set('filament-loginguard.lockout.tracking.per_email', false);
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    $service = app(LoginGuardService::class);

    $service->recordFailure('1.2.3.4', 'a@example.com');
    $service->recordFailure('1.2.3.4', 'a@example.com');

    // Per-pair mode created a single pair-scoped lock.
    $pairLock = LoginGuardLock::query()->where('scope_type', 'pair')->sole();
    expect($pairLock->scope_key)->toBe('1.2.3.4|a@example.com');

    // The "Locked" filter finds the row via the pair lock.
    $stale = LoginAttempt::factory()->create([
        'last_attempt_at' => now()->subMinutes(31),
        'window_started_at' => now()->subMinutes(31),
    ]);

    $service->recordFailure('9.9.9.9', 'stale@example.com');

    // Admin unblock releases all three scopes of the pair.
    $service->releaseLocksForPair('1.2.3.4', 'a@example.com', reason: 'admin_unblock');

    expect(LoginGuardLock::query()->where('scope_type', 'pair')->where('scope_key', '1.2.3.4|a@example.com')->exists())->toBeFalse()
        ->and($service->isLocked('1.2.3.4', 'a@example.com'))->toBeFalse();

    // The unlocked event carries the pair scope and reason.
    $unlocked = SecurityEvent::query()->where('type', SecurityEvent::TYPE_UNLOCKED)->where('metadata->reason', 'admin_unblock')->get();

    expect($unlocked->pluck('metadata.scope_type')->all())->toContain('pair');
});

it('records an unlocked event only when a lock was actually deleted', function () {
    $service = app(LoginGuardService::class);

    // No-op release: no lock row exists, no event must be written.
    expect($service->releaseLock('email', 'nobody@example.com', reason: 'admin_unblock'))->toBe(0)
        ->and(SecurityEvent::query()->where('type', SecurityEvent::TYPE_UNLOCKED)->count())->toBe(0);

    // A real release writes exactly one event with the scope metadata.
    LoginGuardLock::query()->create([
        'scope_type' => 'email',
        'scope_key' => 'someone@example.com',
        'locked_until' => now()->addMinutes(15),
        'escalation_count' => 1,
    ]);

    expect($service->releaseLock('email', 'someone@example.com', reason: 'self_unlock'))->toBe(1);

    $event = SecurityEvent::query()->where('type', SecurityEvent::TYPE_UNLOCKED)->sole();

    expect($event->metadata['scope_type'])->toBe('email')
        ->and($event->metadata['scope_key'])->toBe('someone@example.com')
        ->and($event->metadata['reason'])->toBe('self_unlock');
});

it('carries the lockout scope in lockout_started events', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 2);

    $service = app(LoginGuardService::class);
    $service->recordFailure('1.2.3.4', 'a@example.com');
    $service->recordFailure('1.2.3.4', 'a@example.com');

    $events = SecurityEvent::query()->where('type', SecurityEvent::TYPE_LOCKOUT_STARTED)->get();

    expect($events->pluck('metadata.scope_type')->all())->toEqual(['ip', 'email'])
        ->and($events->pluck('metadata.scope_key')->all())->toContain('1.2.3.4')
        ->and($events->pluck('metadata.scope_key')->all())->toContain('a@example.com');
});

it('accepts maximum-length emails and pair scope keys', function () {
    config()->set('filament-loginguard.lockout.max_attempts', 1);
    config()->set('filament-loginguard.lockout.tracking.per_ip', false);
    config()->set('filament-loginguard.lockout.tracking.per_email', false);

    // Exactly 254 chars: the RFC-5321 maximum path length (64 local + 1 @ +
    // 189 domain). MySQL stores attempts.email as VARCHAR(255) in strict
    // mode, so anything longer than this cannot exist in a real database.
    $longEmail = str_repeat('a', 64) . '@' . str_repeat('b', 177) . '.example.com';

    expect(strlen($longEmail))->toBe(254);

    $service = app(LoginGuardService::class);
    $service->recordFailure('203.0.113.50', $longEmail, 'test');

    // A pair scope key of 45 + 1 + 254 = 300 characters must survive the 320 limit.
    $service->recordFailure('203.0.113.50', $longEmail, 'test');

    expect(LoginGuardLock::query()->where('scope_type', 'pair')->where('scope_key', '203.0.113.50|' . $longEmail)->exists())->toBeTrue()
        ->and($service->isLocked('203.0.113.50', $longEmail))->toBeTrue();

    // Per-pair mode only stores the pair scope — the key holds the full
    // untruncated 300-character email.
    expect(LoginGuardLock::query()->where('scope_type', 'pair')->count())->toBe(1);
});
