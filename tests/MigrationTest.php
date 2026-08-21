<?php

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

it('creates the attempts table with the expected columns', function () {
    expect(Schema::hasTable('filament_loginguard_attempts'))->toBeTrue()
        ->and(Schema::hasColumns('filament_loginguard_attempts', [
            'id',
            'ip',
            'email',
            'attempts',
            'locked_until',
            'lockout_count',
            'last_attempt_at',
            'created_at',
            'updated_at',
        ]))->toBeTrue();
});

it('enforces the unique ip and email pair', function () {
    $data = [
        'ip' => '1.2.3.4',
        'email' => 'a@example.com',
        'attempts' => 0,
        'lockout_count' => 0,
        'created_at' => now(),
        'updated_at' => now(),
    ];

    DB::table('filament_loginguard_attempts')->insert($data);

    expect(fn () => DB::table('filament_loginguard_attempts')->insert($data))
        ->toThrow(QueryException::class);
});
