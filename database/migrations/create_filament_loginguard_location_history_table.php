<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('filament_loginguard_location_history', function (Blueprint $table): void {
            $table->id();
            $table->string('guard');
            // String identifier on purpose: supports integer ids, UUIDs and ULIDs
            // without schema changes. user_type namespaces different user models
            // so `web` user #1 and `admin` user #1 never collide.
            $table->string('user_type');
            $table->string('user_identifier', 191)->index();
            // ISO 3166-1 alpha-2 country code.
            $table->string('country', 2)->nullable();
            $table->unsignedInteger('asn')->nullable();
            $table->timestamp('first_seen_at')->nullable();
            $table->timestamp('last_seen_at')->nullable();

            $table->timestamps();

            $table->unique(['guard', 'user_type', 'user_identifier', 'country', 'asn'], 'loc_hist_unique');
            $table->index(['user_identifier', 'guard']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('filament_loginguard_location_history');
    }
};
