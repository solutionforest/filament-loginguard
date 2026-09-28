<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('filament_loginguard_attempts', function (Blueprint $table) {
            // Start of the currently-counting decay window. Attempts only
            // accumulate while they fall inside one and the same window; the
            // first failure after the window expires starts a fresh window at
            // zero — making `attempts_window_minutes` a true fixed window.
            $table->timestamp('window_started_at')->nullable()->after('last_attempt_at');
        });
    }

    public function down(): void
    {
        Schema::table('filament_loginguard_attempts', function (Blueprint $table) {
            $table->dropColumn('window_started_at');
        });
    }
};
