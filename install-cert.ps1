# Install AvSuite driver certificate to trusted root
# Run as Administrator

param(
    [Parameter(Mandatory=$false)]
    [string]$CertPath = "D:\Dev\AvSuite\avsuite_driver_cert.pfx",

    [Parameter(Mandatory=$false)]
    [string]$CertPassword = "AvSuite2026"
)

# Check if running as admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

if (-not (Test-Path $CertPath)) {
    Write-Error "Certificate file not found: $CertPath"
    exit 1
}

Write-Host "Installing AvSuite driver certificate to Trusted Root CA store..."

# Import certificate to Trusted Root CA
$certSecurePassword = ConvertTo-SecureString $CertPassword -AsPlainText -Force
Import-PfxCertificate -FilePath $CertPath -CertStoreLocation Cert:\LocalMachine\Root -Password $certSecurePassword -Exportable

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Certificate installed successfully"
    Write-Host "Driver signatures will now be trusted without SmartScreen warnings"
    exit 0
} else {
    Write-Error "Failed to install certificate"
    exit 1
}
