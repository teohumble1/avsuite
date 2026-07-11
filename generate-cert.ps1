#Requires -Version 5.1
<#
.SYNOPSIS
    Generate a fresh self-signed code-signing certificate for AvSuite (dev/test only).

.DESCRIPTION
    Creates a SHA-256 code-signing certificate in the CurrentUser\My store and
    exports it to a password-protected PFX. The PFX password is REQUIRED to import
    the cert or sign binaries with it, so - unlike the previous version of this
    script - the password is NOT thrown away: it is printed once and written to a
    sibling ".password.txt" file with a locked-down ACL (owner read/write only).

    Supply your own password with -Password to skip auto-generation.

.PARAMETER CertName
    Common name (CN) of the certificate. Default: "AvSuite Driver".

.PARAMETER OutputPath
    Where to write the .pfx. Default: ".\avsuite_cert.pfx". Keep this OUTSIDE the
    git repo - the private key must never be committed.

.PARAMETER Password
    Optional SecureString for the PFX. If omitted, a strong 24-byte password is
    generated, printed once, and saved next to the PFX.

.PARAMETER ValidYears
    Certificate lifetime in years. Default: 10.

.EXAMPLE
    .\generate-cert.ps1 -OutputPath C:\certs\avsuite_cert.pfx

.NOTES
    Self-signed ONLY. This will NOT clear Windows SmartScreen ("Unknown
    publisher"). Public distribution requires an OV/EV code-signing certificate
    from a trusted CA (Sectigo/DigiCert). See README "Important Limitations".

    A previously-leaked "AvSuite Driver" PFX had its private key exposed in git
    history - do NOT reuse it. This script issues a brand-new key each run.
#>
[CmdletBinding()]
param(
    [string]$CertName   = "AvSuite Driver",
    [string]$OutputPath = "avsuite_cert.pfx",
    [securestring]$Password,
    [ValidateRange(1, 30)]
    [int]$ValidYears    = 10
)

$ErrorActionPreference = 'Stop'

function Write-Step  { param($m) Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok    { param($m) Write-Host "[ok] $m" -ForegroundColor Green }
function Write-Note  { param($m) Write-Host "[!]  $m" -ForegroundColor Yellow }

Write-Host ""
Write-Step "AvSuite self-signed code-signing certificate"
Write-Note "For isolated testing / portfolio use only - NOT a CA-issued cert."
Write-Host ""

# --- Resolve output path (create parent dir if needed) ---------------------------
$OutputPath = [System.IO.Path]::GetFullPath(
    [System.IO.Path]::Combine((Get-Location).Path, $OutputPath))
$outDir = Split-Path -Parent $OutputPath
if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

# --- Warn about existing certs with the same subject (e.g. the leaked one) --------
$existing = @(Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq "CN=$CertName" })
if ($existing.Count -gt 0) {
    Write-Note "$($existing.Count) certificate(s) named 'CN=$CertName' already exist in CurrentUser\My:"
    foreach ($c in $existing) {
        $exp = $c.NotAfter.ToString('yyyy-MM-dd')
        Write-Host "      $($c.Thumbprint)  (expires $exp)"
    }
    Write-Note "A new, independent key will be created below. Retire old/leaked ones."
    Write-Host ""
}

# --- Create the certificate ------------------------------------------------------
Write-Step "Creating certificate in Cert:\CurrentUser\My ..."
$cert = New-SelfSignedCertificate `
    -CertStoreLocation Cert:\CurrentUser\My `
    -Subject "CN=$CertName" `
    -Type CodeSigningCert `
    -KeyExportPolicy Exportable `
    -KeyUsage DigitalSignature `
    -KeySpec Signature `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears($ValidYears) `
    -FriendlyName "$CertName (self-signed code-signing)"

$validFrom = (Get-Date).ToString('yyyy-MM-dd')
$validTo   = $cert.NotAfter.ToString('yyyy-MM-dd')
Write-Ok "Certificate created"
Write-Host "     Subject   : $($cert.Subject)"
Write-Host "     Thumbprint: $($cert.Thumbprint)"
Write-Host "     Algorithm : SHA256 / RSA-3072"
Write-Host "     Valid     : $validFrom to $validTo"
Write-Host ""

# --- Password: use the supplied one, or generate + persist a strong one -----------
$generatedPlain = $null
if (-not $Password) {
    Write-Step "Generating a strong PFX password ..."
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $bytes = [byte[]]::new(24)
        $rng.GetBytes($bytes)
    } finally { $rng.Dispose() }
    # Hex -> no shell-special characters, safe to paste into signtool /p
    $generatedPlain = ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLower()
    $Password = ConvertTo-SecureString -String $generatedPlain -AsPlainText -Force
}

# --- Export the PFX --------------------------------------------------------------
Write-Step "Exporting PFX to: $OutputPath"
Export-PfxCertificate -Cert $cert -FilePath $OutputPath -Password $Password -Force | Out-Null
$pfxSize = (Get-Item $OutputPath).Length
Write-Ok "PFX exported ($pfxSize bytes)"
Write-Host ""

# --- Persist the generated password (locked-down) and surface it once -------------
if ($generatedPlain) {
    $pwFile = "$OutputPath.password.txt"
    Set-Content -Path $pwFile -Value $generatedPlain -NoNewline -Encoding ascii
    try {
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $grant = '"' + $me + ':(R,W)"'
        Start-Process icacls -ArgumentList "`"$pwFile`" /inheritance:r /grant:r $grant" -NoNewWindow -Wait *> $null
    } catch { Write-Note "Could not tighten ACL on $pwFile - restrict it manually." }

    Write-Note "PFX PASSWORD (save it now - it cannot be recovered from the PFX):"
    Write-Host "        $generatedPlain" -ForegroundColor White
    Write-Host "     Also saved to: $pwFile  (owner-only ACL; keep private, never commit)"
    Write-Host ""
}

# --- Guidance --------------------------------------------------------------------
Write-Step "Next steps"
Write-Host "  Sign a driver/binary (add a timestamp so signatures outlive the cert):"
Write-Host '      signtool sign /f "<pfx>" /p <password> /fd sha256 /tr http://timestamp.digicert.com /td sha256 your.sys'
Write-Host ""
Write-Host "  Trust it on an ISOLATED TEST VM only (adds an untrusted root):"
Write-Host '      Import-PfxCertificate -FilePath "<pfx>" -CertStoreLocation Cert:\LocalMachine\Root ...'
Write-Host ""
Write-Note "Self-signed: will NOT clear SmartScreen. Public release needs an OV/EV CA cert."
Write-Host ""
