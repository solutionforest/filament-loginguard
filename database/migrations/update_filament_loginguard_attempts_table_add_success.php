<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('filament_loginguard_attempts', function (Blueprint $table) {
            $table->unsignedInteger('success_count')->default(0)->after('lockout_count');
            $table->timestamp('last_success_at')->nullable()->after('success_count');
        });
    }

    public function down(): void
    {
        Schema::table('filament_loginguard_attempts', function (Blueprint $table) {
            $table->dropColumn(['success_count', 'last_success_at']);
        });
    }
};
