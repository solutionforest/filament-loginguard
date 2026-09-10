<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>@lang('filament-loginguard::loginguard.self_unlock.title')</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f3f4f6; margin: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1); padding: 2.5rem; max-width: 26rem; text-align: center; }
        h1 { font-size: 1.25rem; margin: 0 0 .75rem; }
        p { color: #4b5563; margin: 0; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="card">
        @if ($status === 'success')
            <h1>@lang('filament-loginguard::loginguard.self_unlock.title')</h1>
            <p>@lang('filament-loginguard::loginguard.self_unlock.success')</p>
        @elseif ($status === 'already_used')
            <h1>@lang('filament-loginguard::loginguard.self_unlock.used_title')</h1>
            <p>@lang('filament-loginguard::loginguard.self_unlock.already_used')</p>
        @elseif ($status === 'no_locks')
            <h1>@lang('filament-loginguard::loginguard.self_unlock.title')</h1>
            <p>@lang('filament-loginguard::loginguard.self_unlock.no_locks')</p>
        @else
            <h1>@lang('filament-loginguard::loginguard.self_unlock.invalid_title')</h1>
            <p>@lang('filament-loginguard::loginguard.self_unlock.invalid')</p>
        @endif
    </div>
</body>
</html>
