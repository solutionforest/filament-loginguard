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
                'user_agent' => 'Browser',
                'attempts' => 'Attempts',
                'lockout_count' => 'Lockouts',
                'locked_until' => 'Locked until',
                'last_attempt_at' => 'Last attempt',
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
    ],
];
