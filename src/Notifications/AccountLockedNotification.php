<?php

namespace SolutionForest\FilamentLoginGuard\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class AccountLockedNotification extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(
        public readonly string $ip,
        public readonly string $email,
        public readonly int $minutes,
        public readonly ?string $unlockUrl = null,
    ) {}

    /**
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $mail = (new MailMessage)
            ->subject(__('filament-loginguard::loginguard.notifications.lockout.subject'))
            ->greeting(__('filament-loginguard::loginguard.notifications.lockout.greeting'))
            ->line(__('filament-loginguard::loginguard.notifications.lockout.ip', ['ip' => $this->ip]))
            ->line(__('filament-loginguard::loginguard.notifications.lockout.email', ['email' => $this->email]))
            ->line(__('filament-loginguard::loginguard.notifications.lockout.duration', ['minutes' => $this->minutes]));

        if ($this->unlockUrl !== null) {
            $mail->line(__('filament-loginguard::loginguard.notifications.lockout.unlock_intro'))
                ->action(__('filament-loginguard::loginguard.notifications.lockout.unlock_action'), $this->unlockUrl);
        }

        return $mail;
    }
}
