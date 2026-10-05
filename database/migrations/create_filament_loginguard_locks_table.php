<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('filament_loginguard_locks', function (Blueprint $table): void {
            $table->id();
            // 'ip', 'email' or 'pair' — locks are scoped per key so a self-unlock
            // of the email scope can never clear an IP lock that shares the same
            // attempt row.
            $table->string('scope_type');
            $table->string('scope_key', 191);
            $table->timestamp('locked_until');
            $table->unsignedInteger('escalation_count')->default(0);
            $table->timestamps();

            $table->unique(['scope_type', 'scope_key']);
            $table->index('locked_until');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('filament_loginguard_locks');
    }
};
