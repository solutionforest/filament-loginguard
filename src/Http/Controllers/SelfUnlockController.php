<?php

namespace SolutionForest\FilamentLoginGuard\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\URL;
use SolutionForest\FilamentLoginGuard\LoginGuardService;

class SelfUnlockController extends Controller
{
    /**
     * Show the confirmation page. Nothing is unlocked here — mail scanners and
     * link prefetchers may follow the emailed GET link, so the state change
     * only ever happens on the POST below.
     */
    public function show(Request $request, string $token, LoginGuardService $service)
    {
        if (! URL::hasValidSignature($request)) {
            abort(403);
        }

        if ($service->isUnlockTokenUsed($this->signature($request))) {
            return view('filament-loginguard::unlock-result', [
                'status' => 'already_used',
            ]);
        }

        return view('filament-loginguard::unlock-confirm', [
            'token' => $token,
        ]);
    }

    /**
     * Consume the link and clear the email lock. The signature check, the
     * one-time token guard and the unlock itself all happen here.
     */
    public function unlock(Request $request, string $token, LoginGuardService $service)
    {
        if (! URL::hasValidSignature($request)) {
            abort(403);
        }

        $signature = $this->signature($request);

        if ($service->isUnlockTokenUsed($signature)) {
            return view('filament-loginguard::unlock-result', [
                'status' => 'already_used',
            ]);
        }

        $email = $service->emailForUnlockToken($token);

        if ($email === null) {
            abort(403);
        }

        $unlocked = $service->unlockEmail($email);

        $service->markUnlockTokenUsed($signature, $service->selfUnlockTtlSeconds());
        $service->forgetUnlockToken($token);

        return view('filament-loginguard::unlock-result', [
            'status' => $unlocked > 0 ? 'success' : 'no_locks',
        ]);
    }

    /**
     * The full signed URL is the replay guard: a replay of the same link always
     * produces the same signature, a forged one fails signature validation first.
     */
    private function signature(Request $request): string
    {
        return sha1($request->fullUrl());
    }
}
