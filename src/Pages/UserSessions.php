<?php

namespace SolutionForest\FilamentLoginGuard\Pages;

use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\BulkAction;
use Filament\Actions\ExportAction;
use Filament\Clusters\Cluster;
use Filament\Notifications\Notification;
use Filament\Pages\Page;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\Schema;
use SolutionForest\FilamentLoginGuard\Filament\Exports\UserSessionExporter;
use SolutionForest\FilamentLoginGuard\Models\UserSession;
use SolutionForest\FilamentLoginGuard\Support\AuthorizesPages;

class UserSessions extends Page implements HasTable
{
    use InteractsWithTable;

    protected string $view = 'filament-loginguard::pages.login-guard';

    public static function canAccess(): bool
    {
        if (! static::isEnabled()) {
            return false;
        }

        return AuthorizesPages::canViewSessions();
    }

    public static function shouldRegisterNavigation(): bool
    {
        return static::isEnabled();
    }

    public static function getDefaultSlug(): string
    {
        return filament_loginguard_config_string('filament-loginguard.pages.sessions.slug', 'user-sessions');
    }

    public static function getCluster(): ?string
    {
        $cluster = config('filament-loginguard.pages.sessions.cluster');

        return is_string($cluster) && is_subclass_of($cluster, Cluster::class) ? $cluster : null;
    }

    public static function getNavigationLabel(): string
    {
        return filament_loginguard_config_string(
            'filament-loginguard.pages.sessions.navigation_label',
            filament_loginguard_trans('filament-loginguard::loginguard.sessions.navigation_label'),
        );
    }

    public static function getNavigationIcon(): string
    {
        return filament_loginguard_config_string('filament-loginguard.pages.sessions.navigation_icon', 'heroicon-o-computer-desktop');
    }

    public static function getNavigationGroup(): ?string
    {
        $group = config('filament-loginguard.pages.sessions.navigation_group');

        return is_string($group) ? $group : null;
    }

    public static function getNavigationSort(): ?int
    {
        $sort = config('filament-loginguard.pages.sessions.navigation_sort');

        return is_int($sort) ? $sort : null;
    }

    public function getTitle(): string
    {
        return filament_loginguard_trans('filament-loginguard::loginguard.sessions.title');
    }

    public function getHeading(): string
    {
        return filament_loginguard_trans('filament-loginguard::loginguard.sessions.heading');
    }

    public function table(Table $table): Table
    {
        /** @var Builder<UserSession> $query */
        $query = UserSession::query()->whereNotNull('user_id');

        return $table
            ->query($query)
            ->defaultSort('last_activity', 'desc')
            ->columns([
                TextColumn::make('user_email')
                    ->label(filament_loginguard_trans('filament-loginguard::loginguard.sessions.table.columns.user'))
                    ->placeholder('-'),
                TextColumn::make('ip_address')
                    ->label(filament_loginguard_trans('filament-loginguard::loginguard.sessions.table.columns.ip'))
                    ->placeholder('-')
                    ->searchable(),
                TextColumn::make('device_name')
                    ->label(filament_loginguard_trans('filament-loginguard::loginguard.sessions.table.columns.device'))
                    ->placeholder('-')
                    ->tooltip(fn (UserSession $record): ?string => $record->user_agent),
                TextColumn::make('last_activity')
                    ->label(filament_loginguard_trans('filament-loginguard::loginguard.sessions.table.columns.last_active'))
                    ->state(fn (UserSession $record): string => $record->last_active_label)
                    ->badge()
                    ->color(fn (UserSession $record): string => $record->is_online ? 'success' : 'gray'),
                TextColumn::make('is_new_device')
                    ->label(filament_loginguard_trans('filament-loginguard::loginguard.sessions.table.new_device'))
                    ->state(fn (UserSession $record): ?string => $record->is_new_device
                        ? filament_loginguard_trans('filament-loginguard::loginguard.sessions.table.new')
                        : null)
                    ->badge()
                    ->placeholder('-')
                    ->color('warning'),
            ])
            ->recordActions([
                Action::make('revoke')
                    ->label(filament_loginguard_trans('filament-loginguard::loginguard.sessions.table.actions.revoke'))
                    ->icon('heroicon-o-x-mark')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->visible(fn (UserSession $record): bool => $record->id !== session()->getId()
                        && AuthorizesPages::canRevokeSessions())
                    ->action(function (UserSession $record): void {
                        $record->delete();

                        Notification::make()
                            ->title(filament_loginguard_trans('filament-loginguard::loginguard.sessions.table.actions.revoked'))
                            ->success()
                            ->send();
                    }),
            ])
            ->bulkActions([
                BulkAction::make('revokeMany')
                    ->label(filament_loginguard_trans('filament-loginguard::loginguard.sessions.table.actions.revoke_many'))
                    ->icon('heroicon-o-x-mark')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->visible(fn (): bool => AuthorizesPages::canRevokeSessions())
                    ->action(function (Collection $records): void {
                        /** @var Collection<int, UserSession> $records */

                        // Never revoke the session performing the request — the
                        // admin would log themselves out mid-action.
                        $records
                            ->reject(fn (UserSession $record): bool => $record->id === session()->getId())
                            ->each(function (UserSession $record): void {
                                $record->delete();
                            });
                    }),
            ]);
    }

    /**
     * @return array<int, Action | ActionGroup>
     */
    protected function getHeaderActions(): array
    {
        if (! (bool) config('filament-loginguard.pages.sessions.export', true)) {
            return [];
        }

        return [
            ExportAction::make()
                ->label(filament_loginguard_trans('filament-loginguard::loginguard.export.action'))
                ->exporter(UserSessionExporter::class),
        ];
    }

    protected static function isEnabled(): bool
    {
        return (bool) config('filament-loginguard.pages.sessions.enabled', true)
            && Schema::hasTable(filament_loginguard_config_string('filament-loginguard.sessions.table', 'sessions'));
    }
}
