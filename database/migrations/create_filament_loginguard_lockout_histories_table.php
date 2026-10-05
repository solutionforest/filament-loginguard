<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('filament_loginguard_lockout_histories', function (Blueprint $table) {
            $table->id();
            $table->string('ip', 45)->nullable();
            $table->string('email')->nullable();
            $table->timestamp('locked_at');
            $table->timestamp('locked_until');
            $table->unsignedInteger('lockout_count');
            $table->unsignedInteger('duration_minutes');
            $table->string('triggered_by_ip', 45)->nullable();
            $table->string('triggered_by_email')->nullable();
            $table->timestamps();

            $table->index(['ip', 'email']);
            $table->index('locked_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('filament_loginguard_lockout_histories');
    }
};
