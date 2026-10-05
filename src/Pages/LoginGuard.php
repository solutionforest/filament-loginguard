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
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use SolutionForest\FilamentLoginGuard\Filament\Exports\LoginAttemptExporter;
use SolutionForest\FilamentLoginGuard\LoginGuardService;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;
use SolutionForest\FilamentLoginGuard\Models\LoginGuardLock;
use SolutionForest\FilamentLoginGuard\Support\AuthorizesPages;
use SolutionForest\FilamentLoginGuard\Widgets\FailureTrendChart;
use SolutionForest\FilamentLoginGuard\Widgets\LoginGuardStats;
use SolutionForest\FilamentLoginGuard\Widgets\TopAttackedEmailsChart;
use SolutionForest\FilamentLoginGuard\Widgets\TopSourceIpsChart;

class LoginGuard extends Page implements HasTable
{
    use InteractsWithTable;

    protected string $view = 'filament-loginguard::pages.login-guard';

    /**
     * Filament v5 pages default to "any authenticated panel user"; gate the page
     * behind the pages.attempts config and an optional view ability.
     */
    public static function canAccess(): bool
    {
        if (! (bool) config('filament-loginguard.pages.attempts.enabled', true)) {
            return false;
        }

        return AuthorizesPages::canViewAttempts();
    }

    public static function shouldRegisterNavigation(): bool
    {
        return (bool) config('filament-loginguard.pages.attempts.enabled', true);
    }

    public static function getDefaultSlug(): string
    {
        return (string) (config('filament-loginguard.pages.attempts.slug') ?: 'login-guard');
    }

    public static function getCluster(): ?string
    {
        $cluster = config('filament-loginguard.pages.attempts.cluster');

        return is_string($cluster) && is_subclass_of($cluster, Cluster::class) ? $cluster : null;
    }

    public static function getNavigationLabel(): string
    {
        return (string) (config('filament-loginguard.pages.attempts.navigation_label')
            ?: __('filament-loginguard::loginguard.page.navigation_label'));
    }

    public static function getNavigationIcon(): string
    {
        return (string) (config('filament-loginguard.pages.attempts.navigation_icon')
            ?: 'heroicon-o-shield-exclamation');
    }

    public static function getNavigationGroup(): ?string
    {
        $group = config('filament-loginguard.pages.attempts.navigation_group');

        return is_string($group) ? $group : null;
    }

    public static function getNavigationSort(): ?int
    {
        $sort = config('filament-loginguard.pages.attempts.navigation_sort');

        return is_int($sort) ? $sort : null;
    }

    public function getTitle(): string
    {
        return __('filament-loginguard::loginguard.page.title');
    }

    public function getHeading(): string
    {
        return __('filament-loginguard::loginguard.page.heading');
    }

    /**
     * @return array<int, class-string>
     */
    protected function getHeaderWidgets(): array
    {
        $widgets = [];

        if ((bool) config('filament-loginguard.pages.attempts.stats_widget', true)) {
            $widgets[] = LoginGuardStats::class;
        }

        if ((bool) config('filament-loginguard.pages.attempts.charts', true)) {
            $widgets[] = FailureTrendChart::class;
            $widgets[] = TopAttackedEmailsChart::class;
            $widgets[] = TopSourceIpsChart::class;
        }

        return $widgets;
    }

    public function table(Table $table): Table
    {
        return $table
            ->query(LoginAttempt::query())
            ->defaultSort('last_attempt_at', 'desc')
            ->columns([
                TextColumn::make('ip')
                    ->label(__('filament-loginguard::loginguard.page.table.columns.ip'))
                    ->searchable(),
                TextColumn::make('email')
                    ->label(__('filament-loginguard::loginguard.page.table.columns.email'))
                    ->searchable(),
                TextColumn::make('device_name')
                    ->label(__('filament-loginguard::loginguard.page.table.columns.user_agent'))
                    ->placeholder('-')
                    ->tooltip(fn (LoginAttempt $record): ?string => $record->user_agent),
                TextColumn::make('attempts')
                    ->label(__('filament-loginguard::loginguard.page.table.columns.attempts'))
                    ->badge(),
                TextColumn::make('lockout_count')
                    ->label(__('filament-loginguard::loginguard.page.table.columns.lockout_count'))
                    ->badge()
                    ->toggleable(isToggledHiddenByDefault: true),
                TextColumn::make('locked_until')
                    ->label(__('filament-loginguard::loginguard.page.table.columns.locked_until'))
                    ->state(fn (LoginAttempt $record): ?string => app(LoginGuardService::class)->lockFor($record->ip, $record->email)?->diffForHumans())
                    ->badge()
                    ->placeholder('-')
                    ->color(fn (LoginAttempt $record): string => app(LoginGuardService::class)->isLocked($record->ip, $record->email) ? 'danger' : 'gray'),
                TextColumn::make('last_attempt_at')
                    ->label(__('filament-loginguard::loginguard.page.table.columns.last_attempt_at'))
                    ->state(fn (LoginAttempt $record): ?string => $record->last_attempt_at?->diffForHumans())
                    ->badge()
                    ->placeholder('-')
                    ->color('gray')
                    ->tooltip(fn (LoginAttempt $record): ?string => $record->last_attempt_at?->toDateTimeString()),
                TextColumn::make('success_count')
                    ->label(__('filament-loginguard::loginguard.page.table.columns.success_count'))
                    ->state(fn (LoginAttempt $record): ?int => $record->success_count > 0 ? $record->success_count : null)
                    ->badge()
                    ->placeholder('-')
                    ->color('success'),
                TextColumn::make('last_success_at')
                    ->label(__('filament-loginguard::loginguard.page.table.columns.last_success_at'))
                    ->state(fn (LoginAttempt $record): ?string => $record->last_success_at?->diffForHumans())
                    ->placeholder('-')
                    ->toggleable(isToggledHiddenByDefault: true)
                    ->tooltip(fn (LoginAttempt $record): ?string => $record->last_success_at?->toDateTimeString()),
            ])
            ->filters([
                SelectFilter::make('status')
                    ->label(__('filament-loginguard::loginguard.page.table.filters.status'))
                    ->options([
                        'locked' => __('filament-loginguard::loginguard.page.table.filters.locked'),
                        'tracked' => __('filament-loginguard::loginguard.page.table.filters.tracked'),
                    ])
                    ->query(function (Builder $query, array $data): Builder {
                        return match ($data['value']) {
                            'locked' => $query->where(function (Builder $q): void {
                                // Blocked by either the row's IP lock or its email lock.
                                $q->whereExists(function (\Illuminate\Database\Query\Builder $sub): void {
                                    $sub->selectRaw(1)
                                        ->from('filament_loginguard_locks')
                                        ->whereColumn('scope_key', 'filament_loginguard_attempts.ip')
                                        ->where('scope_type', 'ip')
                                        ->where('locked_until', '>', now());
                                })->orWhereExists(function (\Illuminate\Database\Query\Builder $sub): void {
                                    $sub->selectRaw(1)
                                        ->from('filament_loginguard_locks')
                                        ->whereColumn('scope_key', 'filament_loginguard_attempts.email')
                                        ->where('scope_type', 'email')
                                        ->where('locked_until', '>', now());
                                });
                            }),
                            'tracked' => $query->where('attempts', '>', 0),
                            default => $query,
                        };
                    }),
            ])
            ->recordActions([
                Action::make('unblock')
                    ->label(__('filament-loginguard::loginguard.page.table.actions.unblock'))
                    ->icon('heroicon-o-lock-open')
                    ->color('success')
                    ->requiresConfirmation()
                    ->visible(function (LoginAttempt $record): bool {
                        // Releasing both scopes of this row: the UI treats the
                        // pair as one unit for admins.
                        return app(LoginGuardService::class)->isLocked($record->ip, $record->email)
                            && AuthorizesPages::canUnblockAttempts();
                    })
                    ->action(function (LoginAttempt $record): void {
                        $service = app(LoginGuardService::class);
                        $service->releaseLock(LoginGuardLock::SCOPE_IP, $record->ip);
                        $service->releaseLock(LoginGuardLock::SCOPE_EMAIL, $record->email);

                        Notification::make()
                            ->title(__('filament-loginguard::loginguard.page.table.actions.unblocked'))
                            ->success()
                            ->send();
                    }),
            ])
            ->bulkActions([
                BulkAction::make('unblockMany')
                    ->label(__('filament-loginguard::loginguard.page.table.actions.unblock_many'))
                    ->icon('heroicon-o-lock-open')
                    ->color('success')
                    ->requiresConfirmation()
                    ->visible(fn (): bool => AuthorizesPages::canUnblockAttempts())
                    ->action(function (Collection $records): Collection {
                        $service = app(LoginGuardService::class);

                        $records->each(function (LoginAttempt $record) use ($service): void {
                            $service->releaseLock(LoginGuardLock::SCOPE_IP, $record->ip);
                            $service->releaseLock(LoginGuardLock::SCOPE_EMAIL, $record->email);
                        });

                        return $records;
                    }),
            ]);
    }

    /**
     * @return array<int, Action | ActionGroup>
     */
    protected function getHeaderActions(): array
    {
        if (! (bool) config('filament-loginguard.pages.attempts.export', true)) {
            return [];
        }

        return [
            ExportAction::make()
                ->label(__('filament-loginguard::loginguard.export.action'))
                ->exporter(LoginAttemptExporter::class),
        ];
    }
}
