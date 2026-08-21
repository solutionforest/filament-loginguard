<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('filament_loginguard_attempts', function (Blueprint $table) {
            $table->id();
            $table->string('ip', 45);
            $table->string('email');
            $table->unsignedInteger('attempts')->default(0);
            $table->timestamp('locked_until')->nullable();
            $table->unsignedInteger('lockout_count')->default(0);
            $table->timestamp('last_attempt_at')->nullable();
            $table->timestamps();

            $table->unique(['ip', 'email']);
            $table->index('email');
            $table->index('locked_until');
            $table->index('last_attempt_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('filament_loginguard_attempts');
    }
};
