<?php

namespace SolutionForest\FilamentLoginGuard\Pages;

use Filament\Actions\Action;
use Filament\Actions\BulkAction;
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
use Illuminate\Support\Facades\Auth;
use SolutionForest\FilamentLoginGuard\Models\LoginAttempt;

class LoginGuard extends Page implements HasTable
{
    use InteractsWithTable;

    protected string $view = 'filament-loginguard::pages.login-guard';

    /**
     * Filament v5 pages default to "any authenticated panel user"; gate the page
     * behind the attempts_page config and an optional ability.
     */
    public static function canAccess(): bool
    {
        if (! (bool) config('filament-loginguard.attempts_page.enabled', true)) {
            return false;
        }

        $ability = config('filament-loginguard.attempts_page.authorize');

        if (blank($ability)) {
            return true;
        }

        $user = Auth::user();

        return $user !== null && method_exists($user, 'can') && (bool) $user->can($ability);
    }

    public static function shouldRegisterNavigation(): bool
    {
        return (bool) config('filament-loginguard.attempts_page.enabled', true);
    }

    public static function getDefaultSlug(): string
    {
        return (string) (config('filament-loginguard.attempts_page.slug') ?: 'login-guard');
    }

    public static function getCluster(): ?string
    {
        $cluster = config('filament-loginguard.attempts_page.cluster');

        return is_string($cluster) && is_subclass_of($cluster, Cluster::class) ? $cluster : null;
    }

    public static function getNavigationLabel(): string
    {
        return (string) (config('filament-loginguard.attempts_page.navigation_label')
            ?: __('filament-loginguard::loginguard.page.navigation_label'));
    }

    public static function getNavigationIcon(): string
    {
        return (string) (config('filament-loginguard.attempts_page.navigation_icon')
            ?: 'heroicon-o-shield-exclamation');
    }

    public static function getNavigationGroup(): ?string
    {
        $group = config('filament-loginguard.attempts_page.navigation_group');

        return is_string($group) ? $group : null;
    }

    public static function getNavigationSort(): ?int
    {
        $sort = config('filament-loginguard.attempts_page.navigation_sort');

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
                    ->state(fn (LoginAttempt $record): ?string => $record->isLocked()
                        ? $record->locked_until->diffForHumans()
                        : null)
                    ->badge()
                    ->placeholder('-')
                    ->tooltip(fn (LoginAttempt $record): ?string => $record->locked_until?->toDateTimeString())
                    ->color(fn (LoginAttempt $record): string => $record->isLocked() ? 'danger' : 'gray'),
                TextColumn::make('last_attempt_at')
                    ->label(__('filament-loginguard::loginguard.page.table.columns.last_attempt_at'))
                    ->state(fn (LoginAttempt $record): ?string => $record->last_attempt_at?->diffForHumans())
                    ->badge()
                    ->placeholder('-')
                    ->color('gray')
                    ->tooltip(fn (LoginAttempt $record): ?string => $record->last_attempt_at?->toDateTimeString()),
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
                            'locked' => $query->where('locked_until', '>', now()),
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
                    ->visible(fn (LoginAttempt $record): bool => $record->isLocked())
                    ->action(function (LoginAttempt $record): void {
                        $record->unlock();

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
                    ->action(function (Collection $records): Collection {
                        $records->each(fn (LoginAttempt $record) => $record->unlock());

                        return $records;
                    }),
            ]);
    }
}
