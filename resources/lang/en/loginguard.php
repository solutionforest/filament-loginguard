<?php

return [
    'messages' => [
        'locked' => 'Too many failed login attempts. Access is blocked for :minutes minutes. Please try again later.',
    ],
    'page' => [
        'navigation_label' => 'Login Guard',
        'title' => 'Login Guard',
        'heading' => 'Login Attempts',
        'table' => [
            'columns' => [
                'ip' => 'IP Address',
                'email' => 'Email',
                'user_agent' => 'Device',
                'attempts' => 'Attempts',
                'lockout_count' => 'Lockouts',
                'locked_until' => 'Locked until',
                'last_attempt_at' => 'Last attempt',
                'success_count' => 'Successful',
                'last_success_at' => 'Last success',
            ],
            'filters' => [
                'status' => 'Status',
                'locked' => 'Locked',
                'tracked' => 'With failed attempts',
            ],
            'actions' => [
                'unblock' => 'Unblock',
                'unblock_many' => 'Unblock selected',
                'unblocked' => 'Unblocked',
            ],
        ],
    ],
    'notifications' => [
        'lockout' => [
            'subject' => 'LoginGuard lockout triggered',
            'greeting' => 'A login lockout has been triggered.',
            'ip' => 'IP address: :ip',
            'email' => 'Email: :email',
            'duration' => 'Blocked for :minutes minutes.',
        ],
        'new_device' => [
            'subject' => 'New device login detected',
            'greeting' => 'A login from a new device has been detected.',
            'email' => 'User: :email',
            'device' => 'Device: :device',
            'ip' => 'IP address: :ip',
        ],
    ],
    'sessions' => [
        'navigation_label' => 'User Sessions',
        'title' => 'User Sessions',
        'heading' => 'Active Sessions',
        'table' => [
            'columns' => [
                'user' => 'User',
                'ip' => 'IP Address',
                'device' => 'Device',
                'last_active' => 'Last active',
            ],
            'online_now' => 'Online now',
            'new_device' => 'New device',
            'new' => 'New',
            'actions' => [
                'revoke' => 'Revoke',
                'revoke_many' => 'Revoke selected',
                'revoked' => 'Session revoked',
            ],
        ],
    ],
    'stats' => [
        'failed_attempts_24h' => 'Failed attempts (24h)',
        'locked_out_now' => 'Locked out now',
        'successful_logins_24h' => 'Successful logins (24h)',
        'last_24h' => 'Last 24 hours',
        'active_lockouts' => 'Active lockouts',
    ],
];
