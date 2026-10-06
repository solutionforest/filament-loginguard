<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('filament_loginguard_devices', function (Blueprint $table): void {
            $table->id();
            $table->string('guard')->index();
            // String identifier on purpose: supports integer ids, UUIDs and ULIDs
            // without schema changes. user_type namespaces different user models
            // so `web` user #1 and `admin` user #1 never collide.
            $table->string('user_type');
            $table->string('user_identifier', 191)->index();
            // Only the SHA-256 hash of the opaque cookie token is stored — the
            // raw token lives exclusively in the browser cookie.
            $table->string('token_hash', 64);
            $table->string('device_name')->nullable();
            $table->text('user_agent')->nullable();
            $table->string('first_ip', 45)->nullable();
            $table->string('last_ip', 45)->nullable();
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at');
            // trusted_at is reserved for a future step-up verification flow;
            // a successful password login alone only ever means "recognized".
            $table->timestamp('trusted_at')->nullable();
            $table->timestamp('revoked_at')->nullable();

            $table->timestamps();

            $table->unique(['guard', 'user_type', 'user_identifier', 'token_hash']);
            $table->index(['user_identifier', 'guard']);
            $table->index('revoked_at');
        });

        Schema::create('filament_loginguard_device_sessions', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('device_id')->constrained('filament_loginguard_devices')->cascadeOnDelete();
            $table->string('session_id', 191)->index();
            $table->string('guard');
            $table->timestamp('last_seen_at');

            $table->timestamps();

            $table->unique(['device_id', 'session_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('filament_loginguard_device_sessions');
        Schema::dropIfExists('filament_loginguard_devices');
    }
};
