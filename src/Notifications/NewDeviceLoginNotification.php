<?php

namespace SolutionForest\FilamentLoginGuard\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class NewDeviceLoginNotification extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(
        public readonly string $email,
        public readonly string $device,
        public readonly string $ip,
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
        return (new MailMessage)
            ->subject(__('filament-loginguard::loginguard.notifications.new_device.subject'))
            ->greeting(__('filament-loginguard::loginguard.notifications.new_device.greeting'))
            ->line(__('filament-loginguard::loginguard.notifications.new_device.email', ['email' => $this->email]))
            ->line(__('filament-loginguard::loginguard.notifications.new_device.device', ['device' => $this->device]))
            ->line(__('filament-loginguard::loginguard.notifications.new_device.ip', ['ip' => $this->ip]));
    }
}
