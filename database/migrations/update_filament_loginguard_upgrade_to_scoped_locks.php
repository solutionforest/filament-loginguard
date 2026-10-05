<?php

use Carbon\Carbon;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Repairs the v0.5 → v0.6 upgrade path.
     *
     * v0.6.0 reshaped the lock model but edited already-released migrations,
     * so databases that ran the v0.5 migrations never received the new
     * schema: `lockout_histories.ip/email` stayed NOT NULL (breaking scoped
     * inserts) and the new locks table never received pre-existing locks.
     * This migration brings every upgrade path (fresh, v0.5 → v0.6.1,
     * v0.6.0 → v0.6.1) to the same final schema.
     */
    public function up(): void
    {
        // 1. Lockout history: scope columns become nullable (a scoped history
        //    row fills exactly one of the two columns).
        Schema::table('filament_loginguard_lockout_histories', function (Blueprint $table): void {
            $table->string('ip', 45)->nullable()->change();
            $table->string('email')->nullable()->change();
        });

        // 2. Locks table: widen the scope columns (a pair scope key is up to
        //    45 + 1 + 254 = 300 characters; emails can exceed 191).
        Schema::table('filament_loginguard_locks', function (Blueprint $table): void {
            $table->string('scope_type', 16)->change();
            $table->string('scope_key', 320)->change();
        });

        // 3. Backfill: legacy v0.5 locks (attempts.locked_until) carried both
        //    the IP and the email dimension in one column — the old
        //    matchingRowsQuery() matched locked rows by `ip OR email`, so
        //    restoring the old enforcement means seeding both scopes.
        $legacyLocks = DB::table('filament_loginguard_attempts')
            ->where('locked_until', '>', now())
            ->get(['ip', 'email', 'locked_until']);

        foreach ($legacyLocks as $legacy) {
            $expires = Carbon::parse($legacy->locked_until);

            DB::table('filament_loginguard_locks')->updateOrInsert(
                ['scope_type' => 'ip', 'scope_key' => $legacy->ip],
                ['locked_until' => $expires, 'escalation_count' => 0, 'created_at' => now(), 'updated_at' => now()],
            );

            DB::table('filament_loginguard_locks')->updateOrInsert(
                ['scope_type' => 'email', 'scope_key' => $legacy->email],
                ['locked_until' => $expires, 'escalation_count' => 0, 'created_at' => now(), 'updated_at' => now()],
            );
        }
    }

    public function down(): void
    {
        // Deliberately not reversible: narrowing the scope columns and
        // un-nulling the history columns would destroy scoped data written by
        // v0.6.x. The backfilled locks cannot be told apart from genuine
        // v0.6 locks, so they are left in place (they expire naturally).
    }
};
