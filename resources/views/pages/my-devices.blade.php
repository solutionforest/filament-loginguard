<x-filament-panels::page>
    @php
        [$currentDevice, $activeDevices, $previousDevices, $guard] = $this->devices;
    @endphp

    <div class="flg-my-devices">

        {{-- Intro: subtitle + device count (low-emphasis, under the heading) --}}
        <div class="flg-my-devices__intro">
            <p class="flg-my-devices__subtitle">
                @lang('filament-loginguard::loginguard.my_devices.subtitle')
            </p>
            <p class="flg-my-devices__summary">
                {{ $this->summary }}
            </p>
        </div>

        {{-- ── This device ── --}}
        @if ($currentDevice)
            <section class="flg-my-devices__group">
                <h2 class="flg-my-devices__group-title">
                    @lang('filament-loginguard::loginguard.my_devices.groups.this_device')
                </h2>

                <div class="flg-my-devices__list">
                    <div class="flg-my-devices__row" wire:key="device-{{ $currentDevice->id }}">
                        <span class="flg-my-devices__icon">
                            <x-filament::icon :icon="$this->deviceIcon($currentDevice->user_agent)" />
                        </span>

                        <div class="flg-my-devices__main">
                            <p class="flg-my-devices__name">{{ $this->deviceLabel($currentDevice) }}</p>
                            <p class="flg-my-devices__meta">
                                @lang('filament-loginguard::loginguard.my_devices.labels.last_active')
                                {{ $currentDevice->last_seen_at->diffForHumans() }}
                                &middot;
                                {{ $currentDevice->last_ip ?? __('filament-loginguard::loginguard.devices.unknown_ip') }}
                            </p>
                            <button
                                type="button"
                                class="flg-my-devices__details"
                                wire:click="mountAction('viewDevice', { device: {{ $currentDevice->id }} })"
                            >
                                @lang('filament-loginguard::loginguard.my_devices.actions.view_details')
                            </button>
                        </div>

                        <div class="flg-my-devices__side">
                            <x-filament::badge color="success">
                                @lang('filament-loginguard::loginguard.my_devices.badges.this_device')
                            </x-filament::badge>
                        </div>
                    </div>
                </div>
            </section>
        @endif

        {{-- ── Other signed-in devices ── --}}
        @if ($activeDevices->isNotEmpty())
            <section class="flg-my-devices__group">
                <h2 class="flg-my-devices__group-title">
                    @lang('filament-loginguard::loginguard.my_devices.groups.other_devices')
                </h2>

                <div class="flg-my-devices__list">
                    @foreach ($activeDevices as $device)
                        <div class="flg-my-devices__row" wire:key="device-{{ $device->id }}">
                            <span class="flg-my-devices__icon">
                                <x-filament::icon :icon="$this->deviceIcon($device->user_agent)" />
                            </span>

                            <div class="flg-my-devices__main">
                                <p class="flg-my-devices__name">{{ $this->deviceLabel($device) }}</p>
                                <p class="flg-my-devices__meta">
                                    @lang('filament-loginguard::loginguard.my_devices.labels.last_active')
                                    {{ $device->last_seen_at->diffForHumans() }}
                                    &middot;
                                    {{ $device->last_ip ?? __('filament-loginguard::loginguard.devices.unknown_ip') }}
                                </p>
                                <button
                                    type="button"
                                    class="flg-my-devices__details"
                                    wire:click="mountAction('viewDevice', { device: {{ $device->id }} })"
                                >
                                    @lang('filament-loginguard::loginguard.my_devices.actions.view_details')
                                </button>
                            </div>

                            <div class="flg-my-devices__side">
                                @if ($device->first_seen_at->isAfter(now()->subDay()))
                                    <x-filament::badge color="info">
                                        @lang('filament-loginguard::loginguard.my_devices.badges.new')
                                    </x-filament::badge>
                                @endif

                                <span class="flg-my-devices__sign-out">
                                    <x-filament::button
                                        color="gray"
                                        size="sm"
                                        wire:click="mountAction('signOutDevice', { device: {{ $device->id }} })"
                                    >
                                        @lang('filament-loginguard::loginguard.my_devices.actions.sign_out')
                                    </x-filament::button>
                                </span>

                                <x-filament::dropdown placement="bottom-end" teleport>
                                    <x-slot name="trigger">
                                        <x-filament::icon-button
                                            color="gray"
                                            icon="heroicon-m-ellipsis-vertical"
                                            :label="__('filament-loginguard::loginguard.my_devices.actions.device_actions')"
                                        />
                                    </x-slot>

                                    <x-filament::dropdown.list>
                                        <x-filament::dropdown.list.item
                                            wire:click="mountAction('signOutDevice', { device: {{ $device->id }} })"
                                            icon="heroicon-m-arrow-left-on-rectangle"
                                            class="sm:hidden"
                                        >
                                            @lang('filament-loginguard::loginguard.my_devices.actions.sign_out')
                                        </x-filament::dropdown.list.item>

                                        <x-filament::dropdown.list.item
                                            color="danger"
                                            icon="heroicon-m-exclamation-triangle"
                                            wire:click="mountAction('revokeDevice', { device: {{ $device->id }} })"
                                        >
                                            @lang('filament-loginguard::loginguard.my_devices.actions.this_is_not_me')
                                        </x-filament::dropdown.list.item>
                                    </x-filament::dropdown.list>
                                </x-filament::dropdown>
                            </div>
                        </div>
                    @endforeach
                </div>
            </section>
        @endif

        {{-- ── Recently signed out (collapsible) ── --}}
        @if ($previousDevices->isNotEmpty())
            <section
                class="flg-my-devices__group"
                x-data="{ expanded: false }"
            >
                <div class="flg-my-devices__group-heading">
                    <h2 class="flg-my-devices__group-title">
                        @lang('filament-loginguard::loginguard.my_devices.groups.previous_devices')
                    </h2>

                    <button
                        type="button"
                        class="flg-my-devices__expand"
                        x-on:click="expanded = ! expanded"
                    >
                        <span x-text="expanded ? @js(__('filament-loginguard::loginguard.my_devices.actions.collapse')) : @js(__('filament-loginguard::loginguard.my_devices.actions.expand'))"></span>
                        <x-filament::icon
                            icon="heroicon-m-chevron-down"
                            class="flg-my-devices__expand-icon"
                            x-bind:class="{ 'flg-my-devices__expand-icon--open': expanded }"
                        />
                    </button>
                </div>

                <div class="flg-my-devices__list" x-show="expanded" x-cloak>
                    @foreach ($previousDevices as $device)
                        <div class="flg-my-devices__row flg-my-devices__row--previous" wire:key="device-{{ $device->id }}">
                            <span class="flg-my-devices__icon">
                                <x-filament::icon :icon="$this->deviceIcon($device->user_agent)" />
                            </span>

                            <div class="flg-my-devices__main">
                                <p class="flg-my-devices__name">{{ $this->deviceLabel($device) }}</p>
                                <p class="flg-my-devices__meta">
                                    @lang('filament-loginguard::loginguard.my_devices.labels.signed_out')
                                    &middot;
                                    @lang('filament-loginguard::loginguard.my_devices.labels.last_used', [
                                        'period' => $device->last_seen_at->diffForHumans(),
                                    ])
                                </p>
                            </div>

                            <div class="flg-my-devices__side">
                                <x-filament::dropdown placement="bottom-end" teleport>
                                    <x-slot name="trigger">
                                        <x-filament::icon-button
                                            color="gray"
                                            icon="heroicon-m-ellipsis-vertical"
                                            :label="__('filament-loginguard::loginguard.my_devices.actions.device_actions')"
                                        />
                                    </x-slot>

                                    <x-filament::dropdown.list>
                                        <x-filament::dropdown.list.item
                                            color="gray"
                                            icon="heroicon-m-trash"
                                            wire:click="mountAction('forgetDevice', { device: {{ $device->id }} })"
                                        >
                                            @lang('filament-loginguard::loginguard.my_devices.actions.forget')
                                        </x-filament::dropdown.list.item>
                                    </x-filament::dropdown.list>
                                </x-filament::dropdown>
                            </div>
                        </div>
                    @endforeach
                </div>
            </section>
        @endif

        {{-- ── Only this device ── --}}
        @if ($currentDevice && $activeDevices->isEmpty() && $previousDevices->isEmpty())
            <p class="flg-my-devices__only-here">
                @lang('filament-loginguard::loginguard.my_devices.empty.only_here')
            </p>
        @endif

        {{-- ── No devices at all (defensive) ── --}}
        @if (! $currentDevice && $activeDevices->isEmpty() && $previousDevices->isEmpty())
            <x-filament::empty-state icon="heroicon-o-device-phone-mobile">
                <x-slot name="heading">
                    @lang('filament-loginguard::loginguard.my_devices.empty.title')
                </x-slot>

                <x-slot name="description">
                    @lang('filament-loginguard::loginguard.my_devices.empty.description')
                </x-slot>
            </x-filament::empty-state>
        @endif

    </div>
</x-filament-panels::page>
