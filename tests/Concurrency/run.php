<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use SolutionForest\FilamentLoginGuard\LoginGuardService;
use SolutionForest\FilamentLoginGuard\Models\LockoutHistory;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Models\LoginGuardLock;
use SolutionForest\FilamentLoginGuard\Models\SecurityEvent;
use Symfony\Component\Process\Process;

require __DIR__ . '/bootstrap.php';

const FROZEN_TIME = '2026-01-01 00:00:00';
const WORKER_COUNT = 8;
const BARRIER_TIMEOUT = 10;

date_default_timezone_set('UTC');
Carbon::setTestNow(FROZEN_TIME);

function requireCondition(bool $condition, string $message): void
{
    if (! $condition) {
        throw new RuntimeException($message);
    }
}

function runWorker(string $directory, string $barrier, int $maxAttempts, string $ip, string $email, string $operation): void
{
    requireCondition(is_dir($barrier), 'The worker barrier is missing.');
    concurrencyDatabase($directory, $maxAttempts);
    DB::connection()->getPdo();
    fwrite(STDOUT, "ready\n");

    $deadline = hrtime(true) + BARRIER_TIMEOUT * 1_000_000_000;
    $start = $barrier . '/start';

    while (! is_file($start)) {
        requireCondition(hrtime(true) < $deadline, 'Timed out waiting for the parent to release the start barrier.');
        usleep(1000);
        clearstatcache(true, $start);
    }

    $service = new LoginGuardService;

    if ($operation === 'success') {
        $service->recordSuccess($ip, $email);
        fwrite(STDOUT, "succeeded\n");

        return;
    }

    requireCondition($operation === 'failure', 'Unknown worker operation.');
    $result = $service->recordFailure($ip, $email);
    fwrite(STDOUT, $result->locked ? "locked\n" : "counted\n");
}

/** @param list<array{string, string}> $pairs */
function recordConcurrently(string $directory, string $scenario, array $pairs, int $maxAttempts, string $operation = 'failure'): int
{
    $barrier = $directory . '/' . $scenario;
    requireCondition(mkdir($barrier, 0700), "Cannot create the barrier for [{$scenario}].");

    $workers = [];

    try {
        foreach ($pairs as [$ip, $email]) {
            $process = new Process([PHP_BINARY, __FILE__, 'worker', $directory, $barrier, (string) $maxAttempts, $ip, $email, $operation]);
            $process->setTimeout(BARRIER_TIMEOUT * 2);
            $process->start();
            $workers[] = $process;
        }

        $pending = $workers;
        $deadline = hrtime(true) + BARRIER_TIMEOUT * 1_000_000_000;

        while ($pending !== []) {
            foreach ($pending as $index => $process) {
                if (preg_match('/\Aready\R/', $process->getOutput()) === 1) {
                    unset($pending[$index]);
                } elseif (! $process->isRunning()) {
                    throw new RuntimeException("Worker {$index} exited before the start barrier. " . $process->getErrorOutput());
                }
            }

            requireCondition(hrtime(true) < $deadline, "Workers did not reach the start barrier for [{$scenario}].");
            usleep(1000);
        }

        requireCondition(touch($barrier . '/start'), "Cannot release the start barrier for [{$scenario}].");

        $confirmed = 0;
        $errors = [];
        $successfulOutput = $operation === 'success' ? "ready\nsucceeded\n" : "ready\nlocked\n";
        $validOutputs = $operation === 'success' ? [$successfulOutput] : [$successfulOutput, "ready\ncounted\n"];

        foreach ($workers as $index => $process) {
            $process->wait();
            $output = str_replace("\r\n", "\n", $process->getOutput());

            if (! $process->isSuccessful() || ! in_array($output, $validOutputs, true)) {
                $errors[] = "Worker {$index}: " . trim($process->getErrorOutput());

                continue;
            }

            if ($output === $successfulOutput) {
                $confirmed++;
            }
        }

        requireCondition($errors === [], implode("\n", $errors));

        return $confirmed;
    } finally {
        foreach ($workers as $process) {
            if ($process->isRunning()) {
                $process->stop(0);
            }
        }

        if (is_file($barrier . '/start')) {
            unlink($barrier . '/start');
        }

        rmdir($barrier);
    }
}

function runScenarios(string $directory): int
{
    $service = new LoginGuardService;
    $failures = [];

    $scenario = 'same-pair-first-successes';

    try {
        $pair = ['192.0.2.6', 'first-success@example.test'];
        $confirmed = recordConcurrently($directory, $scenario, array_fill(0, WORKER_COUNT, $pair), 20, operation: 'success');
        [$ip, $email] = $pair;
        $record = LoginAttempt::query()->where('ip', $ip)->where('email', $email)->sole();

        requireCondition($confirmed === WORKER_COUNT, "Expected all workers to record a success, got {$confirmed}.");
        requireCondition($record->success_count === WORKER_COUNT, "Expected eight successes, found {$record->success_count}.");
        requireCondition($record->last_success_at?->toDateTimeString() === FROZEN_TIME, 'The success counter has an incorrect latest timestamp.');

        fwrite(STDOUT, "PASS  {$scenario}\n");
    } catch (Throwable $exception) {
        $failures[] = "{$scenario}: " . $exception->getMessage();
    }

    $unprimedPair = ['192.0.2.4', 'first-failure@example.test'];
    $activePair = ['192.0.2.1', 'active@example.test'];
    $expiredPair = ['192.0.2.2', 'expired@example.test'];
    $ipPairs = [];
    $emailPairs = [];
    $overThresholdPairs = [];

    for ($index = 1; $index <= WORKER_COUNT; $index++) {
        $ipPairs[] = ['192.0.2.3', "ip-{$index}@example.test"];
        $emailPairs[] = ["198.51.100.{$index}", 'shared-email@example.test'];
        $overThresholdPairs[] = ['192.0.2.5', "overflow-{$index}@example.test"];
    }

    foreach ([
        'same-pair-first-failures' => [array_fill(0, WORKER_COUNT, $unprimedPair), WORKER_COUNT + 1, null, null, null],
        'same-pair-existing-window' => [array_fill(0, WORKER_COUNT, $activePair), 20, 0, null, null],
        'same-pair-expired-window' => [array_fill(0, WORKER_COUNT, $expiredPair), 20, 31, null, null],
        'same-ip-different-email' => [$ipPairs, WORKER_COUNT * 2, 0, LoginGuardLock::SCOPE_IP, '192.0.2.3'],
        'same-email-different-ip' => [$emailPairs, WORKER_COUNT * 2, 0, LoginGuardLock::SCOPE_EMAIL, 'shared-email@example.test'],
        'same-ip-over-threshold' => [$overThresholdPairs, 4, null, LoginGuardLock::SCOPE_IP, '192.0.2.5'],
    ] as $scenario => [$pairs, $maxAttempts, $seedAgeMinutes, $lockScope, $lockKey]) {
        try {
            if ($seedAgeMinutes !== null) {
                Carbon::setTestNow(now()->subMinutes($seedAgeMinutes));

                foreach ($lockScope === null ? [$pairs[0]] : $pairs as [$ip, $email]) {
                    $service->recordFailure($ip, $email);
                }
            }

            Carbon::setTestNow(FROZEN_TIME);
            $confirmed = recordConcurrently($directory, $scenario, $pairs, $maxAttempts);

            if ($lockScope === null) {
                [$ip, $email] = $pairs[0];
                $record = LoginAttempt::query()->where('ip', $ip)->where('email', $email)->sole();
                $expected = WORKER_COUNT + (int) ($seedAgeMinutes === 0);
                requireCondition($record->attempts === $expected, "Expected {$expected} attempts, found {$record->attempts}.");
                requireCondition($record->window_started_at?->toDateTimeString() === FROZEN_TIME, 'The active counter has an incorrect window start.');
                requireCondition($confirmed === 0 && ! $service->isLocked($ip, $email), 'The pair should remain below the lock threshold.');
                requireCondition(
                    LockoutHistory::query()->where('ip', $ip)->orWhere('email', $email)->doesntExist(),
                    'A below-threshold pair should have no lockout history.',
                );
            } else {
                $expected = $seedAgeMinutes === null ? 1 : 2;

                foreach ($pairs as [$ip, $email]) {
                    $record = LoginAttempt::query()->where('ip', $ip)->where('email', $email)->sole();
                    requireCondition($record->attempts === $expected, "Expected {$expected} attempts for [{$ip}, {$email}], found {$record->attempts}.");
                }

                $lock = LoginGuardLock::activeQuery()->where('scope_type', $lockScope)->where('scope_key', $lockKey)->first();
                requireCondition($lock?->escalation_count === 1, "Expected the first aggregate lock on [{$lockScope}:{$lockKey}].");
                requireCondition($lock->locked_until->equalTo(now()->addMinutes(15)), 'The first aggregate lock should keep its original expiry.');
                requireCondition($confirmed === 1, "Expected exactly one new lockout, but {$confirmed} workers reported one.");
                $historyColumn = $lockScope === LoginGuardLock::SCOPE_IP ? 'ip' : 'email';
                requireCondition(LockoutHistory::query()->where($historyColumn, $lockKey)->count() === 1, 'Expected one lockout history entry.');
                requireCondition(SecurityEvent::query()->where('type', SecurityEvent::TYPE_LOCKOUT_STARTED)->where($historyColumn, $lockKey)->count() === 1, 'Expected one lockout event.');
            }

            fwrite(STDOUT, "PASS  {$scenario}\n");
        } catch (Throwable $exception) {
            $failures[] = "{$scenario}: " . $exception->getMessage();
        } finally {
            Carbon::setTestNow(FROZEN_TIME);
        }
    }

    foreach ($failures as $failure) {
        fwrite(STDERR, "FAIL  {$failure}\n");
    }

    return $failures === [] ? 0 : 1;
}

function runConcurrencySuite(): int
{
    $directory = sys_get_temp_dir() . '/loginguard-concurrency-' . bin2hex(random_bytes(10));
    requireCondition(mkdir($directory, 0700), 'Cannot create the isolated concurrency test directory.');
    $applied = [];

    try {
        requireCondition(touch($directory . '/database.sqlite'), 'Cannot create the temporary SQLite database.');
        $container = concurrencyDatabase($directory, 100);

        foreach (concurrencyMigrations($container) as $migration) {
            $migration->up();
            $applied[] = $migration;
        }

        return runScenarios($directory);
    } finally {
        if (getenv('LOGINGUARD_CONCURRENCY_CONNECTION') === 'mysql') {
            foreach (array_reverse($applied) as $migration) {
                $migration->down();
            }
        }

        foreach ((glob($directory . '/database.sqlite*') ?: []) as $databaseFile) {
            unlink($databaseFile);
        }

        rmdir($directory);
    }
}

try {
    if (($argv[1] ?? null) === 'worker') {
        requireCondition($argc === 8, 'Invalid worker arguments.');
        runWorker($argv[2], $argv[3], (int) $argv[4], $argv[5], $argv[6], $argv[7]);
        exit(0);
    }

    requireCondition($argc === 1, 'Run without arguments to execute the concurrency suite.');
    exit(runConcurrencySuite());
} catch (Throwable $exception) {
    fwrite(STDERR, $exception->getMessage() . PHP_EOL);
    exit(1);
}
