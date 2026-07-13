#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Web Guard hardening tool. Reports, applies, or reverts a null-route + firewall
    block of known malicious-JavaScript infrastructure (cryptomining pools, Magecart
    skimmer gates, malvertising / exploit-kit gates, tracker-C2).

.DESCRIPTION
    The Web Guard dashboard tab watches browser connections to this IOC list in real
    time. This script turns that list into an actual, machine-wide block:
      1. Hosts file  -> null-route (0.0.0.0) every IOC host, between managed markers
      2. Firewall    -> one outbound Block rule covering every IP the IOC hosts resolve to

    Idempotent and fully reversible. -Revert removes the managed hosts block and the
    firewall rule; nothing else on the system is touched.

.PARAMETER Status   Report current block state (read-only, default).
.PARAMETER Apply    Null-route the IOC hosts + add the firewall block rule.
.PARAMETER Revert   Remove the managed hosts block + firewall rule.

.EXAMPLE
    .\Harden-WebGuard.ps1 -Status
.EXAMPLE
    .\Harden-WebGuard.ps1 -Apply
.EXAMPLE
    .\Harden-WebGuard.ps1 -Revert

.NOTES
    Run elevated. The IOC list mirrors the Web Guard tab's blocklist
    (docs/web-guard-threat-research.md) and is safe to null-route: these are
    cryptominer / skimmer / malvertising / exploit-kit domains, not OS or CDN hosts.
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Status')][switch]$Status,
    [Parameter(ParameterSetName = 'Apply')][switch]$Apply,
    [Parameter(ParameterSetName = 'Revert')][switch]$Revert
)

$ErrorActionPreference = 'Stop'

function Line { param($m) Write-Host $m }
function Head { param($m) Write-Host "`n== $m ==" -ForegroundColor Cyan }
function Good { param($m) Write-Host "  [ok]   $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "  [!]    $m" -ForegroundColor Yellow }
function Info { param($m) Write-Host "  [..]   $m" -ForegroundColor Gray }

$HostsPath  = "$env:SystemRoot\System32\drivers\etc\hosts"
$HostsBegin = "# >>> WebGuard BEGIN (managed - do not edit inside) >>>"
$HostsEnd   = "# <<< WebGuard END <<<"
$FwRuleName = "WebGuard - malicious JavaScript infrastructure"

# IOC hosts (mirror of the Web Guard tab's kBadHosts). Cryptomining pools/miner-JS
# still resolve live; historical EK/skimmer gates are kept as IOCs.
$BadHosts = @(
    # Cryptojacking
    'coinhive.com','coin-hive.com','authedmine.com','cnhv.co','coinimp.com',
    'www.coinimp.com','minero.cc','crypto-loot.com','cryptoloot.pro',
    'webminepool.com','webmine.cz','jsecoin.com','load.jsecoin.com','ppoi.org',
    # Magecart / skimmer
    'magento-analytics.com','google-analytics.top','googie-anaiytics.com',
    'jquery-cdn.top','cdn-js.link','ajaxstatic.com',
    # Malvertising
    'go.oclaserver.com','onclickpredictiv.com','adnium.com','propu.pl',
    # Tracker / C2
    'stat-analytics.info','track-cdn.net'
)

function Show-Status {
    Head "Web Guard block status"

    $blocked = 0
    if (Test-Path $HostsPath) {
        $h = Get-Content $HostsPath -Raw
        $blocked = ($BadHosts | Where-Object { $h -match [regex]::Escape($_) }).Count
    }
    if ($blocked -eq 0) { Warn "Hosts file: 0 / $($BadHosts.Count) IOC hosts null-routed" }
    else { Good "Hosts file: $blocked / $($BadHosts.Count) IOC hosts null-routed" }

    $rule = Get-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue
    if ($rule) { Good "Firewall rule present ($($rule.Enabled))" } else { Warn "Firewall block rule: none" }
    Line ""
}

function Set-HostsBlock {
    $existing = if (Test-Path $HostsPath) { Get-Content $HostsPath -Raw } else { '' }
    $pattern = "(?s)\r?\n?" + [regex]::Escape($HostsBegin) + ".*?" + [regex]::Escape($HostsEnd)
    $clean = [regex]::Replace($existing, $pattern, '').TrimEnd()
    $block = @($HostsBegin) + ($BadHosts | ForEach-Object { "0.0.0.0 $_" }) + @($HostsEnd)
    $out = ($clean + "`r`n" + ($block -join "`r`n") + "`r`n").TrimStart("`r", "`n")
    Set-Content -Path $HostsPath -Value $out -Encoding ascii -Force
}

function Set-FirewallRule {
    try {
        if (Get-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue) {
            Good "firewall: rule already present"; return
        }
        # Resolve whatever IOC hosts are still live; block the union of their IPs.
        $ips = foreach ($badHost in $BadHosts) {
            (Resolve-DnsName $badHost -Type A -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress }).IPAddress
        }
        $ips = $ips | Where-Object { $_ } | Sort-Object -Unique
        if ($ips) {
            New-NetFirewallRule -DisplayName $FwRuleName -Direction Outbound -Action Block `
                -RemoteAddress $ips -Profile Any -ErrorAction Stop | Out-Null
            Good "firewall: outbound block on $($ips.Count) IOC IP(s)"
        } else {
            Info "firewall: no IOC host currently resolves; hosts-file block still active"
        }
    } catch { Warn "firewall step skipped: $($_.Exception.Message)" }
}

function Invoke-Apply {
    Head "Applying Web Guard block"
    Set-HostsBlock
    Good "hosts: $($BadHosts.Count) malicious-JS hosts null-routed to 0.0.0.0"
    Set-FirewallRule
    Line ""
    Line "Re-run with -Status to confirm, or -Revert to undo."
}

function Invoke-Revert {
    Head "Reverting Web Guard block"
    if (Test-Path $HostsPath) {
        $h = Get-Content $HostsPath -Raw
        $pattern = "(?s)\r?\n?" + [regex]::Escape($HostsBegin) + ".*?" + [regex]::Escape($HostsEnd)
        Set-Content $HostsPath -Value ([regex]::Replace($h, $pattern, '').TrimEnd() + "`r`n") -Encoding ascii -Force
        Good "hosts: managed block removed"
    }
    if (Get-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue
        Good "firewall rule removed"
    }
    Line ""
}

switch ($PSCmdlet.ParameterSetName) {
    'Apply'  { Invoke-Apply;  Line ""; Show-Status }
    'Revert' { Invoke-Revert; Line ""; Show-Status }
    default  { Show-Status }
}
