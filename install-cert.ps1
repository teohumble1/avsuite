#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Trust the AvSuite self-signed code-signing certificate on an ISOLATED TEST VM.

.DESCRIPTION
    Installs ONLY the PUBLIC certificate from the given PFX into the machine's
    Trusted Root Certification Authorities and Trusted Publishers stores, so a
    driver signed with the matching private key can load under test-signing.

    The private key is NEVER imported into the Root store (it is not needed to
    trust a signature, and putting a signing key in Root is a security smell).

    The PFX password is read from a sibling "<pfx>.password.txt" (written by
    generate-cert.ps1) when present; otherwise you are prompted for it.

.PARAMETER CertPath
    Path to the .pfx produced by generate-cert.ps1. Default: ".\avsuite_cert.pfx".

.NOTES
    TEST VM ONLY. Adding an untrusted root weakens the machine's trust chain --
    never do this on a real/host machine. This does NOT remove SmartScreen
    "Unknown publisher" on downloaded files (SmartScreen reputation is separate
    from certificate trust); only an OV/EV CA certificate does that.
#>
[CmdletBinding()]
param(
    [string]$CertPath = "avsuite_cert.pfx"
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $CertPath)) {
    Write-Error "Certificate file not found: $CertPath"
    exit 1
}
$CertPath = (Resolve-Path $CertPath).Path

# --- Obtain the PFX password: sibling file first, else prompt ---------------------
$pwFile = "$CertPath.password.txt"
if (Test-Path $pwFile) {
    Write-Host "Reading PFX password from: $pwFile"
    $plain = (Get-Content $pwFile -Raw).Trim()
    $CertPassword = ConvertTo-SecureString -String $plain -AsPlainText -Force
} else {
    Write-Host "Enter the certificate password (printed by generate-cert.ps1):"
    $CertPassword = Read-Host -AsSecureString
}

# --- Load ONLY the public certificate (no private key import) ---------------------
Write-Host "Loading certificate ..."
try {
    $pfx  = Get-PfxData -FilePath $CertPath -Password $CertPassword
    $cert = $pfx.EndEntityCertificates[0]
} catch {
    Write-Error "Could not open the PFX (wrong password?): $($_.Exception.Message)"
    exit 1
}
Write-Host "  Subject   : $($cert.Subject)"
Write-Host "  Thumbprint: $($cert.Thumbprint)"

$tmpCer = Join-Path $env:TEMP "avsuite_pubcert_$($cert.Thumbprint).cer"
Export-Certificate -Cert $cert -FilePath $tmpCer -Force | Out-Null

# --- Import the public cert into the trust stores kernel driver loading checks ----
try {
    foreach ($store in @('Root', 'TrustedPublisher')) {
        Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null
        Write-Host "[ok] Installed to LocalMachine\$store"
    }
} catch {
    Write-Error "Failed to install certificate: $($_.Exception.Message)"
    exit 1
} finally {
    Remove-Item $tmpCer -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "[ok] Certificate trusted on this machine (TEST VM)."
Write-Host "     A driver signed with the matching key can now load under test-signing"
Write-Host "     (enable it once with: bcdedit /set testsigning on  + reboot)."
Write-Host ""
Write-Host "[!]  This does NOT remove SmartScreen 'Unknown publisher' on downloaded"
Write-Host "     files -- that requires an OV/EV certificate from a trusted CA."
