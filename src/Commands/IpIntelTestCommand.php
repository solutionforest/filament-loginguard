<?php

namespace SolutionForest\FilamentLoginGuard\Commands;

use Illuminate\Console\Command;
use SolutionForest\FilamentLoginGuard\Services\IpIntelligence;
use SolutionForest\FilamentLoginGuard\Support\IpAddress;

class IpIntelTestCommand extends Command
{
    public $signature = 'filament-loginguard:ip-intel:test {ip? : An IP address to look up (defaults to 8.8.8.8)}';

    public $description = 'Diagnose the IP intelligence (GeoIP) setup and test a lookup';

    public function handle(): int
    {
        $ip = IpAddress::normalize((string) ($this->argument('ip') ?? '8.8.8.8'));

        $this->line('IP intelligence (GeoIP) diagnostics');

        $enabled = (bool) config('filament-loginguard.ip_intel.enabled', false);
        $this->line('Enabled: ' . ($enabled ? 'yes' : 'no'));

        $installed = class_exists('GeoIp2\Database\Reader');
        $this->line('geoip2/geoip2 package: ' . ($installed ? 'installed' : 'missing'));

        foreach (['country', 'city', 'asn'] as $kind) {
            $path = config("filament-loginguard.ip_intel.databases.{$kind}");
            $status = is_string($path) && $path !== '' && is_file($path)
                ? $path
                : 'not configured / file missing';

            $this->line("  {$kind}: {$status}");
        }

        // Force-enable for the lookup so diagnostics work even before the
        // master switch is flipped; restore the original value afterwards.
        $original = config('filament-loginguard.ip_intel.enabled');
        config()->set('filament-loginguard.ip_intel.enabled', true);

        try {
            $location = app(IpIntelligence::class)->lookup($ip);
        } finally {
            config()->set('filament-loginguard.ip_intel.enabled', $original);
        }

        if ($location === null) {
            $this->error("Lookup for {$ip} returned no result.");

            return self::FAILURE;
        }

        $this->line("Lookup for {$ip}:");

        foreach ($location->toArray() as $key => $value) {
            if ($value !== null) {
                $this->line("  {$key}: {$value}");
            }
        }

        return self::SUCCESS;
    }
}
