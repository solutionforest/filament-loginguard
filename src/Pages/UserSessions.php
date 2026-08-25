<?php

namespace SolutionForest\FilamentLoginGuard\Pages;

use Filament\Actions\Action;
use Filament\Actions\BulkAction;
use Filament\Notifications\Notification;
use Filament\Pages\Page;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use SolutionForest\FilamentLoginGuard\Models\UserSession;

class UserSessions extends Page implements HasTable
{
    use InteractsWithTable;

    protected string $view = 'filament-loginguard::pages.login-guard';

    public static function canAccess(): bool
    {
        if (! static::isEnabled()) {
            return false;
        }

        $ability = config('filament-loginguard.sessions.page.authorize');

        if (blank($ability)) {
            return true;
        }

        $user = Auth::user();

        return $user !== null && method_exists($user, 'can') && (bool) $user->can($ability);
    }

    public static function shouldRegisterNavigation(): bool
    {
        return static::isEnabled();
    }

    public static function getDefaultSlug(): string
    {
        return (string) (config('filament-loginguard.sessions.page.slug') ?: 'user-sessions');
    }

    public static function getNavigationLabel(): string
    {
        return (string) (config('filament-loginguard.sessions.page.navigation_label')
            ?: __('filament-loginguard::loginguard.sessions.navigation_label'));
    }

    public static function getNavigationIcon(): string
    {
        return (string) (config('filament-loginguard.sessions.page.navigation_icon')
            ?: 'heroicon-o-computer-desktop');
    }

    public static function getNavigationGroup(): ?string
    {
        $group = config('filament-loginguard.sessions.page.navigation_group');

        return is_string($group) ? $group : null;
    }

    public static function getNavigationSort(): ?int
    {
        $sort = config('filament-loginguard.sessions.page.navigation_sort');

        return is_int($sort) ? $sort : null;
    }

    public function getTitle(): string
    {
        return __('filament-loginguard::loginguard.sessions.title');
    }

    public function getHeading(): string
    {
        return __('filament-loginguard::loginguard.sessions.heading');
    }

    public function table(Table $table): Table
    {
        return $table
            ->query(UserSession::query())
            ->defaultSort('last_activity', 'desc')
            ->columns([
                TextColumn::make('user_email')
                    ->label(__('filament-loginguard::loginguard.sessions.table.columns.user'))
                    ->placeholder('-'),
                TextColumn::make('ip_address')
                    ->label(__('filament-loginguard::loginguard.sessions.table.columns.ip'))
                    ->placeholder('-')
                    ->searchable(),
                TextColumn::make('device_name')
                    ->label(__('filament-loginguard::loginguard.sessions.table.columns.device'))
                    ->placeholder('-')
                    ->tooltip(fn (UserSession $record): ?string => $record->user_agent),
                TextColumn::make('last_activity')
                    ->label(__('filament-loginguard::loginguard.sessions.table.columns.last_active'))
                    ->state(fn (UserSession $record): string => $record->last_active_label)
                    ->badge()
                    ->color(fn (UserSession $record): string => $record->is_online ? 'success' : 'gray'),
            ])
            ->recordActions([
                Action::make('revoke')
                    ->label(__('filament-loginguard::loginguard.sessions.table.actions.revoke'))
                    ->icon('heroicon-o-x-mark')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->visible(fn (UserSession $record): bool => $record->id !== session()->getId())
                    ->action(function (UserSession $record): void {
                        $record->delete();

                        Notification::make()
                            ->title(__('filament-loginguard::loginguard.sessions.table.actions.revoked'))
                            ->success()
                            ->send();
                    }),
            ])
            ->bulkActions([
                BulkAction::make('revokeMany')
                    ->label(__('filament-loginguard::loginguard.sessions.table.actions.revoke_many'))
                    ->icon('heroicon-o-x-mark')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->action(function (Collection $records): void {
                        $records->each(fn (UserSession $record) => $record->delete());
                    }),
            ]);
    }

    protected static function isEnabled(): bool
    {
        return (bool) config('filament-loginguard.sessions.enabled', true)
            && Schema::hasTable((string) config('filament-loginguard.sessions.table', 'sessions'));
    }
}
