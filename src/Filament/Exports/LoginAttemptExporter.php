<?php

namespace SolutionForest\FilamentLoginGuard\Filament\Exports;

use Filament\Actions\Exports\Enums\ExportFormat;
use Filament\Actions\Exports\ExportColumn;
use Filament\Actions\Exports\Exporter;
use Filament\Actions\Exports\Models\Export;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;

class LoginAttemptExporter extends Exporter
{
    protected static ?string $model = LoginAttempt::class;

    /**
     * @return array<int, ExportColumn>
     */
    public static function getColumns(): array
    {
        return [
            ExportColumn::make('ip'),
            ExportColumn::make('email')
                ->preventFormulaInjection(),
            ExportColumn::make('device_name'),
            ExportColumn::make('attempts'),
            ExportColumn::make('lockout_count'),
            ExportColumn::make('locked_until'),
            ExportColumn::make('last_attempt_at'),
            ExportColumn::make('success_count'),
            ExportColumn::make('last_success_at'),
        ];
    }

    /**
     * @return array<int, ExportFormat>
     */
    public function getFormats(): array
    {
        return [ExportFormat::Csv];
    }

    public function getFileName(Export $export): string
    {
        return "login-attempts-{$export->getKey()}.csv";
    }

    public static function getCompletedNotificationBody(Export $export): string
    {
        $successful = number_format($export->successful_rows);
        $failed = $export->getFailedRowsCount();

        $body = __('filament-loginguard::loginguard.export.completed', ['count' => $successful]);

        if ($failed > 0) {
            $body .= ' ' . __('filament-loginguard::loginguard.export.failed', ['count' => number_format($failed)]);
        }

        return $body;
    }
}
