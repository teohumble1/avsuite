<#
.SYNOPSIS
    (Re)register AvSuite's AMSI provider using a RELEASE build of avamsi.dll.

.DESCRIPTION
    AvSuite's AMSI provider is registered system-wide (HKLM), so Windows loads it
    into EVERY AMSI host (avdashboard, PowerShell, Office macros, ...). If a DEBUG
    avamsi.dll ever gets registered (e.g. a stray `regsvr32` during testing), it
    pulls in the debug CRT (ucrtbased.dll) and dies on a debug assert
    (STATUS_BREAKPOINT 0x80000003), crashing whichever process loaded it.

    This script guarantees the RELEASE build is the one registered: it unregisters
    whatever is currently registered (or clears a dangling registration whose DLL
    no longer exists) and then registers the release avamsi.dll.

    Run from an ELEVATED PowerShell. Requires the 'release' CMake preset to have
    been built first.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    # Unregister only, don't re-register (mirrors the installer's uninstall step).
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'
$clsid = '{14261D4E-E150-42C6-BD96-E27EFE322F86}'
$inproc = "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
$providerKey = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\$clsid"

function Clear-Registration {
    $current = (Get-ItemProperty $inproc -ErrorAction SilentlyContinue).'(default)'
    if (-not $current) { return }
    if (Test-Path $current) {
        Write-Host "Unregistering current provider: $current"
        Start-Process regsvr32.exe -ArgumentList '/s', '/u', "`"$current`"" -Wait
    } else {
        # DLL is gone -> DllUnregisterServer can't run; delete the keys directly.
        Write-Host "Clearing dangling registration (DLL missing): $current"
        Remove-Item $providerKey -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "HKLM:\SOFTWARE\Classes\CLSID\$clsid" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Clear-Registration

if ($Unregister) {
    Write-Host "AMSI provider unregistered."
    return
}

$root = $PSScriptRoot
# Prefer the pure-Release build (what the installer ships); fall back to RelWithDebInfo.
$candidates = @(
    "$root\build\release\src\amsi_provider\Release\avamsi.dll",
    "$root\build\release\src\amsi_provider\RelWithDebInfo\avamsi.dll"
)
$dll = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $dll) {
    throw "No release avamsi.dll found. Build the 'release' preset first: cmake --build --preset release"
}

Write-Host "Registering RELEASE AMSI provider: $dll"
$p = Start-Process regsvr32.exe -ArgumentList '/s', "`"$dll`"" -Wait -PassThru
if ($p.ExitCode -ne 0) { throw "regsvr32 failed (exit $($p.ExitCode))" }

$now = (Get-ItemProperty $inproc -ErrorAction SilentlyContinue).'(default)'
Write-Host "OK. AMSI provider now registered to:`n  $now"
