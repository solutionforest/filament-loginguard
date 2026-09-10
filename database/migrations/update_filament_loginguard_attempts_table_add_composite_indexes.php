<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('filament_loginguard_attempts', function (Blueprint $table) {
            // Cover the per-IP and per-email aggregate SUM queries in
            // recordFailure(): WHERE ip = ? AND last_attempt_at >= ? (and the
            // email variant). The standalone last_attempt_at index is kept for
            // the cleanup command's date-range scan.
            $table->index(['ip', 'last_attempt_at'], 'filament_loginguard_attempts_ip_last_attempt_index');
            $table->index(['email', 'last_attempt_at'], 'filament_loginguard_attempts_email_last_attempt_index');
        });
    }

    public function down(): void
    {
        Schema::table('filament_loginguard_attempts', function (Blueprint $table) {
            $table->dropIndex('filament_loginguard_attempts_ip_last_attempt_index');
            $table->dropIndex('filament_loginguard_attempts_email_last_attempt_index');
        });
    }
};
