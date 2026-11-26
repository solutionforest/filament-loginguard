<?php

namespace SolutionForest\FilamentLoginGuard\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use SolutionForest\FilamentLoginGuard\Pages\MyDevices;

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
        $mail = (new MailMessage)
            ->subject(filament_loginguard_trans('filament-loginguard::loginguard.notifications.new_device.subject'))
            ->greeting(filament_loginguard_trans('filament-loginguard::loginguard.notifications.new_device.greeting'))
            ->line(filament_loginguard_trans('filament-loginguard::loginguard.notifications.new_device.email', ['email' => $this->email]))
            ->line(filament_loginguard_trans('filament-loginguard::loginguard.notifications.new_device.device', ['device' => $this->device]))
            ->line(filament_loginguard_trans('filament-loginguard::loginguard.notifications.new_device.ip', ['ip' => $this->ip]));

        try {
            $devicesPageEnabled = class_exists(MyDevices::class)
                && (bool) config('filament-loginguard.pages.my_devices.enabled', true)
                && MyDevices::canAccess();
        } catch (\Throwable) {
            // No panel configured (e.g. notification rendering outside a panel).
            $devicesPageEnabled = false;
        }

        if ($devicesPageEnabled) {
            $mail->action(filament_loginguard_trans('filament-loginguard::loginguard.notifications.new_device.review_devices'), MyDevices::getUrl());
        }

        return $mail;
    }
}
