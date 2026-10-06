@php
    use SolutionForest\FilamentLoginGuard\Support\ParsesUserAgent;

    $deviceName = $device?->device_name ?? __('filament-loginguard::loginguard.devices.unknown_device');
    $unknown = __('filament-loginguard::loginguard.my_devices.labels.unknown');
@endphp

<div class="flg-device-details">
    <dl class="flg-device-details__list">
        <div class="flg-device-details__row">
            <dt class="flg-device-details__label">@lang('filament-loginguard::loginguard.my_devices.labels.client')</dt>
            <dd class="flg-device-details__value">{{ $deviceName }}</dd>
        </div>

        <div class="flg-device-details__row">
            <dt class="flg-device-details__label">@lang('filament-loginguard::loginguard.my_devices.labels.browser')</dt>
            <dd class="flg-device-details__value">{{ $browser ?? $unknown }}</dd>
        </div>

        <div class="flg-device-details__row">
            <dt class="flg-device-details__label">@lang('filament-loginguard::loginguard.my_devices.labels.os')</dt>
            <dd class="flg-device-details__value">{{ $os ?? $unknown }}</dd>
        </div>

        <div class="flg-device-details__row">
            <dt class="flg-device-details__label">@lang('filament-loginguard::loginguard.my_devices.labels.first_seen')</dt>
            <dd class="flg-device-details__value">{{ $device?->first_seen_at?->isoFormat('LLLL') ?? $unknown }}</dd>
        </div>

        <div class="flg-device-details__row">
            <dt class="flg-device-details__label">@lang('filament-loginguard::loginguard.my_devices.labels.last_active')</dt>
            <dd class="flg-device-details__value">{{ $device?->last_seen_at?->isoFormat('LLLL') ?? $unknown }}</dd>
        </div>

        <div class="flg-device-details__row">
            <dt class="flg-device-details__label">@lang('filament-loginguard::loginguard.my_devices.labels.last_ip')</dt>
            <dd class="flg-device-details__value">{{ $device?->last_ip ?? __('filament-loginguard::loginguard.devices.unknown_ip') }}</dd>
        </div>

        <div class="flg-device-details__row">
            <dt class="flg-device-details__label">@lang('filament-loginguard::loginguard.my_devices.labels.active_sessions')</dt>
            <dd class="flg-device-details__value">{{ trans_choice('filament-loginguard::loginguard.my_devices.labels.sessions', $sessionCount, ['count' => $sessionCount]) }}</dd>
        </div>
    </dl>

    <div class="flg-device-details__ua">
        <p class="flg-device-details__label">@lang('filament-loginguard::loginguard.my_devices.labels.user_agent')</p>
        <p class="flg-device-details__ua-value">{{ $device?->user_agent ?? $unknown }}</p>
    </div>
</div>
