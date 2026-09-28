<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>@lang('filament-loginguard::loginguard.self_unlock.confirm_title')</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f3f4f6; margin: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1); padding: 2.5rem; max-width: 26rem; text-align: center; }
        h1 { font-size: 1.25rem; margin: 0 0 .75rem; }
        p { color: #4b5563; margin: 0 0 1.5rem; line-height: 1.6; }
        form { display: inline-block; }
        button { background: #dc2626; border: 0; border-radius: 6px; color: #fff; cursor: pointer; font-size: .95rem; padding: .6rem 1.25rem; }
        button:hover { background: #b91c1c; }
    </style>
</head>
<body>
    <div class="card">
        <h1>@lang('filament-loginguard::loginguard.self_unlock.confirm_title')</h1>
        <p>@lang('filament-loginguard::loginguard.self_unlock.confirm_intro')</p>
        <form method="POST" action="{{ url()->current() }}">
            @csrf
            <button type="submit">@lang('filament-loginguard::loginguard.self_unlock.confirm_action')</button>
        </form>
    </div>
</body>
</html>
