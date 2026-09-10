<?php

namespace SolutionForest\FilamentLoginGuard\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\URL;
use SolutionForest\FilamentLoginGuard\LoginGuardService;

class SelfUnlockController extends Controller
{
    public function __invoke(Request $request, string $email, LoginGuardService $service)
    {
        if (! URL::hasValidSignature($request)) {
            abort(403);
        }

        $signature = sha1($request->fullUrl());
        $ttlSeconds = max(1, (int) config('filament-loginguard.lockout.notifications.self_unlock.link_ttl_minutes', 60)) * 60;

        if ($service->isUnlockTokenUsed($signature)) {
            return view('filament-loginguard::unlock-result', [
                'status' => 'already_used',
            ]);
        }

        $unlocked = $service->unlockEmail($email);

        $service->markUnlockTokenUsed($signature, $ttlSeconds);

        return view('filament-loginguard::unlock-result', [
            'status' => $unlocked > 0 ? 'success' : 'no_locks',
        ]);
    }
}
