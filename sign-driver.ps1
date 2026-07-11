# Code-signing script for AvMiniFilter driver.
#
# Default path is fully non-interactive: it signs with a certificate already
# in the current user's store, selected by thumbprint. This is what actually
# works for the VM test flow (WDKTestCert) and never blocks a headless build.
#
# Fallback: pass -CertPath <file.pfx> to sign from a PFX instead. Only then is
# a password required; supply it with -PfxPassword (SecureString) or, if
# omitted AND the session is interactive, you will be prompted.
#
# IMPORTANT: keep this file pure ASCII. The vcxproj post-build invokes it via
# Windows PowerShell 5.1, which reads the script as ANSI -- a stray non-ASCII
# byte (e.g. a checkmark) byte-misaligns and breaks parsing.
param(
    [Parameter(Mandatory = $true)]
    [string]$DriverPath,

    # Store-based signing (default). WDKTestCert "teohumble".
    [string]$Thumbprint = "3FF9BDFD6742D0A7B6B969AB8B4E0A7654B266D8",

    # PFX-based signing (optional alternative to -Thumbprint).
    [string]$CertPath,
    [System.Security.SecureString]$PfxPassword,

    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

# Locate signtool (prefer the newest x64 in the WDK/SDK bin).
$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $signtool) {
    Write-Error "signtool.exe not found under Windows Kits 10 bin."
    exit 1
}
if (-not (Test-Path $DriverPath)) {
    Write-Error "Driver file not found: $DriverPath"
    exit 1
}

Write-Host "signtool: $signtool"
Write-Host "Signing: $DriverPath"

if ($CertPath) {
    # ---- PFX path (needs a password) ----
    if (-not (Test-Path $CertPath)) {
        Write-Error "Cert file not found: $CertPath"
        exit 1
    }
    if (-not $PfxPassword) {
        if ([Environment]::UserInteractive) {
            Write-Host "Enter the PFX password:"
            $PfxPassword = Read-Host -AsSecureString
        } else {
            Write-Error "PFX signing needs -PfxPassword in a non-interactive session."
            exit 1
        }
    }
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($PfxPassword)
    try {
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($bstr)
        & $signtool sign /f $CertPath /p $plain /fd SHA256 /td SHA256 /tr $TimestampUrl $DriverPath
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($bstr)
    }
} else {
    # ---- Store thumbprint path (non-interactive, default) ----
    if (-not (Test-Path "Cert:\CurrentUser\My\$Thumbprint") -and
        -not (Test-Path "Cert:\LocalMachine\My\$Thumbprint")) {
        Write-Error "Signing cert with thumbprint $Thumbprint not found in CurrentUser\My or LocalMachine\My."
        exit 1
    }
    & $signtool sign /sha1 $Thumbprint /fd SHA256 /td SHA256 /tr $TimestampUrl $DriverPath
}

if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Driver signed successfully"
    exit 0
} else {
    Write-Error "Failed to sign driver (signtool exit $LASTEXITCODE)"
    exit 1
}
