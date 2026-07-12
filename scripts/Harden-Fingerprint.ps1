#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Reduce this machine's device-fingerprinting surface (anti-tracking).

.DESCRIPTION
    Companion to Harden-Telemetry.ps1, driven by the AvSuite "Fingerprint Guard"
    tab. Hardens the identifiers used to fingerprint / track a device:
      1. Advertising ID          -> disabled (HKCU + HKLM policy)
      2. MAC address             -> randomised on Wi-Fi/Ethernet adapters
      3. Fingerprint/tracker DNS -> null-routed in the hosts file (marked block)
    Every change is idempotent and reversible with -Revert.

.PARAMETER Status  Report current state (default, read-only).
.PARAMETER Apply   Apply all hardening.
.PARAMETER Revert  Undo all hardening.
.NOTES
    Self-signed / local hardening only. Browser canvas/WebGL/font fingerprinting
    is a browser concern (needs an extension) and is out of scope here; this
    targets OS-level identifiers + tracker DNS.
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Status')][switch]$Status,
    [Parameter(ParameterSetName = 'Apply')][switch]$Apply,
    [Parameter(ParameterSetName = 'Revert')][switch]$Revert
)
$ErrorActionPreference = 'Stop'

function Head { param($m) Write-Host "`n== $m ==" -ForegroundColor Cyan }
function Ok   { param($m) Write-Host "  [ok] $m" -ForegroundColor Green }
function Note { param($m) Write-Host "  [!]  $m" -ForegroundColor Yellow }

$HostsPath  = "$env:SystemRoot\System32\drivers\etc\hosts"
$HostsBegin = "# >>> FingerprintGuard BEGIN (managed) >>>"
$HostsEnd   = "# <<< FingerprintGuard END <<<"

# Known fingerprinting / tracker / analytics endpoints (safe to null-route).
$TrackerHosts = @(
    'fpjs.io', 'api.fpjs.io', 'fingerprintjs.com', 'cdn.fingerprint.com'
    'www.google-analytics.com', 'ssl.google-analytics.com', 'analytics.google.com'
    'stats.g.doubleclick.net', 'ad.doubleclick.net', 'securepubads.g.doubleclick.net'
    'b.scorecardresearch.com', 'sb.scorecardresearch.com'
    'pixel.rubiconproject.com', 'cdn.mxpnl.com', 'api.mixpanel.com'
    'script.hotjar.com', 'static.hotjar.com', 'in.hotjar.com'
    'cdn.branch.io', 'app.link', 'bat.bing.com'
)

$AdKeyHKCU = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
$AdKeyHKLM = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'

function Get-Adapters {
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Where-Object { $_.MediaType -match '802.3|Native 802.11' }
}

function Show-Status {
    Head "Fingerprint surface"
    $ad = (Get-ItemProperty $AdKeyHKCU -Name Enabled -ErrorAction SilentlyContinue).Enabled
    if ($ad -eq 0) { Ok "Advertising ID: disabled" } else { Note "Advertising ID: ENABLED" }

    foreach ($a in Get-Adapters) {
        $rnd = (Get-NetAdapterAdvancedProperty -Name $a.Name -RegistryKeyword 'NetworkAddress' -ErrorAction SilentlyContinue).RegistryValue
        if ($rnd) { Ok "$($a.Name): MAC overridden ($rnd)" } else { Note "$($a.Name): factory MAC ($($a.MacAddress))" }
    }

    $blocked = 0
    if (Test-Path $HostsPath) {
        $h = Get-Content $HostsPath -Raw
        $blocked = ($TrackerHosts | Where-Object { $h -match [regex]::Escape($_) }).Count
    }
    if ($blocked -gt 0) { Ok "Tracker DNS blocked: $blocked / $($TrackerHosts.Count)" }
    else { Note "Tracker DNS blocked: 0 / $($TrackerHosts.Count)" }
    Write-Host ""
}

function Set-HostsBlock {
    $existing = if (Test-Path $HostsPath) { Get-Content $HostsPath -Raw } else { '' }
    $pattern = "(?s)\r?\n?" + [regex]::Escape($HostsBegin) + ".*?" + [regex]::Escape($HostsEnd)
    $clean = [regex]::Replace($existing, $pattern, '').TrimEnd()
    $block = @($HostsBegin) + ($TrackerHosts | ForEach-Object { "0.0.0.0 $_" }) + @($HostsEnd)
    Set-Content $HostsPath -Value (($clean + "`r`n" + ($block -join "`r`n") + "`r`n").TrimStart("`r","`n")) -Encoding ascii -Force
}

function Invoke-Apply {
    Head "Applying fingerprint hardening"
    # 1. Advertising ID off
    New-Item -Path $AdKeyHKCU -Force | Out-Null
    New-ItemProperty $AdKeyHKCU -Name Enabled -PropertyType DWord -Value 0 -Force | Out-Null
    New-Item -Path $AdKeyHKLM -Force | Out-Null
    New-ItemProperty $AdKeyHKLM -Name DisabledByGroupPolicy -PropertyType DWord -Value 1 -Force | Out-Null
    Ok "Advertising ID disabled"

    # 2. Randomise MAC on each physical adapter
    foreach ($a in Get-Adapters) {
        $mac = ((@('02') + (1..5 | ForEach-Object { '{0:X2}' -f (Get-Random -Max 256) })) -join '')
        try {
            Set-NetAdapterAdvancedProperty -Name $a.Name -RegistryKeyword 'NetworkAddress' -RegistryValue $mac -ErrorAction Stop
            Restart-NetAdapter -Name $a.Name -ErrorAction SilentlyContinue
            Ok "$($a.Name): MAC randomised -> $mac"
        } catch { Note "$($a.Name): adapter does not allow MAC override" }
    }

    # 3. Tracker DNS block
    Set-HostsBlock
    Ok "$($TrackerHosts.Count) tracker/fingerprint hosts null-routed"
    Write-Host ""
    Note "Restarting adapters briefly drops the network; reconnect is automatic."
}

function Invoke-Revert {
    Head "Reverting fingerprint hardening"
    Remove-ItemProperty $AdKeyHKCU -Name Enabled -ErrorAction SilentlyContinue
    if (Test-Path $AdKeyHKLM) { Remove-ItemProperty $AdKeyHKLM -Name DisabledByGroupPolicy -ErrorAction SilentlyContinue }
    Ok "Advertising ID restored to default"

    foreach ($a in Get-Adapters) {
        try {
            Set-NetAdapterAdvancedProperty -Name $a.Name -RegistryKeyword 'NetworkAddress' -RegistryValue '' -ErrorAction Stop
            Restart-NetAdapter -Name $a.Name -ErrorAction SilentlyContinue
            Ok "$($a.Name): factory MAC restored"
        } catch {}
    }

    if (Test-Path $HostsPath) {
        $h = Get-Content $HostsPath -Raw
        $pattern = "(?s)\r?\n?" + [regex]::Escape($HostsBegin) + ".*?" + [regex]::Escape($HostsEnd)
        Set-Content $HostsPath -Value ([regex]::Replace($h, $pattern, '').TrimEnd() + "`r`n") -Encoding ascii -Force
        Ok "tracker DNS block removed"
    }
    Write-Host ""
}

switch ($PSCmdlet.ParameterSetName) {
    'Apply'  { Invoke-Apply;  Show-Status }
    'Revert' { Invoke-Revert; Show-Status }
    default  { Show-Status }
}
