<?php

namespace SolutionForest\FilamentLoginGuard\Filament\Exports;

use Filament\Actions\Exports\Enums\ExportFormat;
use Filament\Actions\Exports\ExportColumn;
use Filament\Actions\Exports\Exporter;
use Filament\Actions\Exports\Models\Export;
use SolutionForest\FilamentLoginGuard\Models\UserSession;

class UserSessionExporter extends Exporter
{
    protected static ?string $model = UserSession::class;

    /**
     * @return array<int, ExportColumn>
     */
    public static function getColumns(): array
    {
        return [
            ExportColumn::make('user_email')
                ->preventFormulaInjection(),
            ExportColumn::make('ip_address'),
            ExportColumn::make('device_name'),
            ExportColumn::make('last_active_at'),
            ExportColumn::make('is_new_device'),
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
        return "user-sessions-{$export->getKey()}.csv";
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
