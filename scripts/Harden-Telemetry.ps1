#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows 10/11 telemetry-hardening tool. Reports, applies, or reverts a set of
    privacy layers that reduce Microsoft telemetry and enforce encrypted DNS.

.DESCRIPTION
    Addresses the gaps a typical telemetry audit surfaces:
      1. AllowTelemetry policy            -> lowest the edition allows
      2. DiagTrack + dmwappushservice     -> stopped + disabled
      3. Telemetry scheduled tasks        -> disabled
      4. Hosts file                       -> block known telemetry endpoints
      5. DNS-over-HTTPS (DoH)             -> enforced (encrypted DNS, no UDP fallback)
      6. Firewall                         -> block the main telemetry host by rule

    Every change is idempotent and reversible: -Revert undoes each layer, the hosts
    block lives between explicit markers, and service/registry originals are restored
    to sane defaults.

.PARAMETER Status
    Report the current state of every layer. No changes. (Default.)

.PARAMETER Apply
    Apply all hardening layers.

.PARAMETER Revert
    Undo all hardening layers (restore services to Automatic, remove the hosts block,
    drop the DoH "require" flag, remove the firewall rule, clear the policy value).

.PARAMETER DohProvider
    Which encrypted-DNS resolver to enforce when applying: Cloudflare (default),
    Quad9, or Google.

.EXAMPLE
    # See what's currently open (safe, read-only)
    .\Harden-Telemetry.ps1 -Status

.EXAMPLE
    # Harden, using Quad9 for encrypted DNS
    .\Harden-Telemetry.ps1 -Apply -DohProvider Quad9

.EXAMPLE
    # Roll everything back
    .\Harden-Telemetry.ps1 -Revert

.NOTES
    Run in an elevated PowerShell. Windows 11 Home cannot go below AllowTelemetry=1
    (Basic/Required) - the policy is still set but the OS clamps it. Enforcing DoH
    changes the active adapter's DNS servers; -Revert sets them back to DHCP/automatic.
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Status')][switch]$Status,
    [Parameter(ParameterSetName = 'Apply')][switch]$Apply,
    [Parameter(ParameterSetName = 'Revert')][switch]$Revert,
    [ValidateSet('Cloudflare', 'Quad9', 'Google')][string]$DohProvider = 'Cloudflare'
)

$ErrorActionPreference = 'Stop'

# ---- output helpers -------------------------------------------------------------
function Line   { param($m) Write-Host $m }
function Head   { param($m) Write-Host "`n== $m ==" -ForegroundColor Cyan }
function Good   { param($m) Write-Host "  [ok]   $m" -ForegroundColor Green }
function Warn   { param($m) Write-Host "  [!]    $m" -ForegroundColor Yellow }
function Info   { param($m) Write-Host "  [..]   $m" -ForegroundColor Gray }

# ---- shared constants -----------------------------------------------------------
$HostsPath   = "$env:SystemRoot\System32\drivers\etc\hosts"
$HostsBegin  = "# >>> TelemetryBlock BEGIN (managed - do not edit inside) >>>"
$HostsEnd    = "# <<< TelemetryBlock END <<<"
$FwRuleName  = "TelemetryBlock - vortex.data.microsoft.com"
$DiagServices = 'DiagTrack', 'dmwappushservice'

# Curated Microsoft telemetry endpoints (safe to null-route; not update/activation).
$TelemetryHosts = @(
    'vortex.data.microsoft.com'
    'vortex-win.data.microsoft.com'
    'telecommand.telemetry.microsoft.com'
    'telemetry.microsoft.com'
    'watson.telemetry.microsoft.com'
    'watson.microsoft.com'
    'settings-win.data.microsoft.com'
    'v10.events.data.microsoft.com'
    'v20.events.data.microsoft.com'
    'v10.vortex-win.data.microsoft.com'
    'us.vortex-win.data.microsoft.com'
    'eu.vortex-win.data.microsoft.com'
    'oca.telemetry.microsoft.com'
    'sqm.telemetry.microsoft.com'
    'browser.events.data.msn.com'
)

# Scheduled tasks that feed the telemetry pipeline (CEIP / appraiser / usage).
$TelemetryTasks = @(
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser'
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater'
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator'
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip'
    '\Microsoft\Windows\Autochk\Proxy'
    '\Microsoft\Windows\Feedback\Siuf\DmClient'
    '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload'
)

$DohMap = @{
    Cloudflare = @{ IP = '1.1.1.1'; Template = 'https://cloudflare-dns.com/dns-query' }
    Quad9      = @{ IP = '9.9.9.9'; Template = 'https://dns.quad9.net/dns-query' }
    Google     = @{ IP = '8.8.8.8'; Template = 'https://dns.google/dns-query' }
}

# =================================================================================
#  STATUS
# =================================================================================
function Show-Status {
    Head "Telemetry / privacy status"

    # 1. AllowTelemetry
    $dc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    $at = (Get-ItemProperty $dc -Name AllowTelemetry -ErrorAction SilentlyContinue).AllowTelemetry
    if ($null -eq $at) { Warn "AllowTelemetry policy: not set (OS default applies)" }
    else { Good "AllowTelemetry policy = $at" }

    # 2. Services
    foreach ($s in $DiagServices) {
        $svc = Get-Service $s -ErrorAction SilentlyContinue
        if (-not $svc) { Info "$s : not present"; continue }
        $start = (Get-CimInstance Win32_Service -Filter "Name='$s'").StartMode
        $msg = "$s : $($svc.Status) / $start"
        if ($svc.Status -eq 'Running') { Warn $msg } else { Good $msg }
    }

    # 3. Scheduled tasks
    $enabled = 0
    foreach ($t in $TelemetryTasks) {
        $p = Split-Path $t; $n = Split-Path $t -Leaf
        $task = Get-ScheduledTask -TaskPath "$p\" -TaskName $n -ErrorAction SilentlyContinue
        if ($task -and $task.State -ne 'Disabled') { $enabled++ }
    }
    if ($enabled -gt 0) { Warn "Telemetry scheduled tasks enabled: $enabled / $($TelemetryTasks.Count)" }
    else { Good "Telemetry scheduled tasks: all disabled/absent" }

    # 4. Hosts
    $blocked = 0
    if (Test-Path $HostsPath) {
        $h = Get-Content $HostsPath -Raw
        $blocked = ($TelemetryHosts | Where-Object { $h -match [regex]::Escape($_) }).Count
    }
    if ($blocked -eq 0) { Warn "Hosts file: 0 telemetry hosts blocked" }
    else { Good "Hosts file: $blocked / $($TelemetryHosts.Count) telemetry hosts blocked" }

    # 5. DoH
    $doh = @(Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)
    if ($doh.Count -eq 0) { Warn "DoH: no encrypted-DNS server configured" }
    else {
        $forced = $doh | Where-Object { $_.AllowFallbackToUdp -eq $false }
        if ($forced) { Good "DoH: enforced ($($forced[0].ServerAddress), no UDP fallback)" }
        else { Warn "DoH: known but not enforced (UDP fallback still allowed)" }
    }

    # 6. Firewall
    $rule = Get-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue
    if ($rule) { Good "Firewall rule present ($($rule.Enabled))" } else { Warn "Firewall telemetry rule: none" }
    Line ""
}

# =================================================================================
#  APPLY
# =================================================================================
function Invoke-Apply {
    Head "Applying telemetry hardening"

    # 1. AllowTelemetry -> 0 (edition clamps to its minimum; Home => effective 1)
    $dc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    New-Item -Path $dc -Force | Out-Null
    New-ItemProperty $dc -Name AllowTelemetry     -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty $dc -Name MaxTelemetryAllowed -PropertyType DWord -Value 1 -Force | Out-Null
    Good "AllowTelemetry policy set to 0 (OS clamps to edition minimum)"

    # 2. Services -> stop + disable
    foreach ($s in $DiagServices) {
        if (-not (Get-Service $s -ErrorAction SilentlyContinue)) { continue }
        try { Stop-Service $s -Force -ErrorAction SilentlyContinue } catch {}
        try { Set-Service $s -StartupType Disabled -ErrorAction Stop }
        catch { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$s" -Name Start -Value 4 }
        Good "$s stopped + disabled"
    }

    # 3. Scheduled tasks -> disable
    foreach ($t in $TelemetryTasks) {
        $p = Split-Path $t; $n = Split-Path $t -Leaf
        try { Disable-ScheduledTask -TaskPath "$p\" -TaskName $n -ErrorAction Stop | Out-Null; Good "task disabled: $n" }
        catch { Info "task not present: $n" }
    }

    # 4. Hosts block (idempotent: rewrite the managed block between markers)
    Set-HostsBlock
    Good "hosts: $($TelemetryHosts.Count) telemetry hosts null-routed to 0.0.0.0"

    # 5. Enforce DoH on the active adapter
    Set-Doh
    # 6. Firewall rule for the primary telemetry host
    Set-FirewallRule

    Line ""
    Warn "Some changes take effect after a reboot (telemetry service teardown)."
    Line "Re-run with -Status to confirm, or -Revert to undo everything."
}

function Set-HostsBlock {
    $existing = if (Test-Path $HostsPath) { Get-Content $HostsPath -Raw } else { '' }
    # strip any prior managed block
    $pattern = "(?s)\r?\n?" + [regex]::Escape($HostsBegin) + ".*?" + [regex]::Escape($HostsEnd)
    $clean = [regex]::Replace($existing, $pattern, '').TrimEnd()
    $block = @($HostsBegin) + ($TelemetryHosts | ForEach-Object { "0.0.0.0 $_" }) + @($HostsEnd)
    $out = ($clean + "`r`n" + ($block -join "`r`n") + "`r`n").TrimStart("`r", "`n")
    Set-Content -Path $HostsPath -Value $out -Encoding ascii -Force
}

function Set-Doh {
    $p = $DohMap[$DohProvider]
    try {
        # Register/refresh the DoH template so Windows knows the resolver
        if (-not (Get-DnsClientDohServerAddress -ServerAddress $p.IP -ErrorAction SilentlyContinue)) {
            Add-DnsClientDohServerAddress -ServerAddress $p.IP -DohTemplate $p.Template -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop | Out-Null
        } else {
            Set-DnsClientDohServerAddress -ServerAddress $p.IP -DohTemplate $p.Template -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop | Out-Null
        }
        # Point the active (up, non-loopback) adapters at the DoH resolver
        $ifs = Get-NetAdapter -Physical | Where-Object Status -eq 'Up'
        foreach ($if in $ifs) {
            Set-DnsClientServerAddress -InterfaceIndex $if.ifIndex -ServerAddresses $p.IP -ErrorAction Stop
        }
        Good "DoH enforced via $DohProvider ($($p.IP)), UDP fallback off"
    } catch {
        Warn "DoH step skipped: $($_.Exception.Message)"
    }
}

function Set-FirewallRule {
    try {
        if (-not (Get-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue)) {
            $ips = (Resolve-DnsName vortex.data.microsoft.com -ErrorAction SilentlyContinue |
                    Where-Object { $_.IPAddress }).IPAddress
            if ($ips) {
                New-NetFirewallRule -DisplayName $FwRuleName -Direction Outbound -Action Block `
                    -RemoteAddress $ips -Profile Any -ErrorAction Stop | Out-Null
                Good "firewall: outbound block on vortex.data.microsoft.com"
            } else { Info "firewall: could not resolve host, rule skipped" }
        } else { Good "firewall: rule already present" }
    } catch { Warn "firewall step skipped: $($_.Exception.Message)" }
}

# =================================================================================
#  REVERT
# =================================================================================
function Invoke-Revert {
    Head "Reverting telemetry hardening"

    # 1. Clear policy
    $dc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    foreach ($v in 'AllowTelemetry', 'MaxTelemetryAllowed') {
        Remove-ItemProperty $dc -Name $v -ErrorAction SilentlyContinue
    }
    Good "AllowTelemetry policy cleared (OS default restored)"

    # 2. Services -> back to Automatic (DiagTrack default) / Manual (dmwappushservice)
    $defaults = @{ DiagTrack = 'Automatic'; dmwappushservice = 'Manual' }
    foreach ($s in $DiagServices) {
        if (-not (Get-Service $s -ErrorAction SilentlyContinue)) { continue }
        try { Set-Service $s -StartupType $defaults[$s] -ErrorAction Stop; Good "$s restored to $($defaults[$s])" }
        catch { Warn "$s : could not restore start type" }
    }

    # 3. Scheduled tasks -> re-enable
    foreach ($t in $TelemetryTasks) {
        $p = Split-Path $t; $n = Split-Path $t -Leaf
        try { Enable-ScheduledTask -TaskPath "$p\" -TaskName $n -ErrorAction Stop | Out-Null; Good "task re-enabled: $n" } catch {}
    }

    # 4. Remove managed hosts block
    if (Test-Path $HostsPath) {
        $h = Get-Content $HostsPath -Raw
        $pattern = "(?s)\r?\n?" + [regex]::Escape($HostsBegin) + ".*?" + [regex]::Escape($HostsEnd)
        Set-Content $HostsPath -Value ([regex]::Replace($h, $pattern, '').TrimEnd() + "`r`n") -Encoding ascii -Force
        Good "hosts: telemetry block removed"
    }

    # 5. DoH -> allow UDP fallback again + adapters back to DHCP
    try {
        Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | ForEach-Object {
            Set-DnsClientDohServerAddress -ServerAddress $_.ServerAddress -AllowFallbackToUdp $true -ErrorAction SilentlyContinue | Out-Null
        }
        Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object {
            Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
        }
        Good "DNS reset to automatic (DHCP), DoH no longer forced"
    } catch { Warn "DoH revert partial: $($_.Exception.Message)" }

    # 6. Firewall rule
    if (Get-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue
        Good "firewall rule removed"
    }
    Line ""
}

# =================================================================================
#  main
# =================================================================================
switch ($PSCmdlet.ParameterSetName) {
    'Apply'  { Invoke-Apply;  Line ""; Show-Status }
    'Revert' { Invoke-Revert; Line ""; Show-Status }
    default  { Show-Status }
}
