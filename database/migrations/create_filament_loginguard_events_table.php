<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
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
    }

    public function down(): void
    {
        Schema::dropIfExists('filament_loginguard_events');
    }
};
