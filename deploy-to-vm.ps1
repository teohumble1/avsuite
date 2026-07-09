# Deploy AvSuite to test VM with certificate setup
# This script handles certificate installation and driver deployment

param(
    [Parameter(Mandatory=$true)]
    [string]$VMPath,

    [Parameter(Mandatory=$false)]
    [string]$DriverSource = "D:\Dev\AvSuite\driver\AvMiniFilter\x64\Release\AvMiniFilter.sys",

    [Parameter(Mandatory=$false)]
    [string]$CertSource = "D:\Dev\AvSuite\avsuite_driver_cert.pfx",

    [Parameter(Mandatory=$false)]
    [string]$CertPassword = "AvSuite2026"
)

Write-Host "================================"
Write-Host "AvSuite VM Deployment"
Write-Host "================================"

# Verify files exist
if (-not (Test-Path $DriverSource)) {
    Write-Error "Driver not found: $DriverSource"
    exit 1
}

if (-not (Test-Path $CertSource)) {
    Write-Error "Certificate not found: $CertSource"
    exit 1
}

Write-Host "✓ Driver: $DriverSource"
Write-Host "✓ Certificate: $CertSource"

# Create destination folder if needed
if (-not (Test-Path $VMPath)) {
    New-Item -ItemType Directory -Path $VMPath -Force | Out-Null
}

# Copy files
Write-Host "`nCopying files to: $VMPath"
Copy-Item $DriverSource -Destination "$VMPath\AvMiniFilter.sys" -Force
Copy-Item $CertSource -Destination "$VMPath\avsuite_driver_cert.pfx" -Force
Copy-Item "D:\Dev\AvSuite\install-cert.ps1" -Destination "$VMPath\install-cert.ps1" -Force

Write-Host "✓ Files copied successfully"

# Create setup script for VM
$setupScript = @"
# Run this in the VM as Administrator
`$CertPath = '`$PSScriptRoot\avsuite_driver_cert.pfx'
`$CertPassword = '$CertPassword'
`$DriverPath = '`$PSScriptRoot\AvMiniFilter.sys'

Write-Host "AvSuite VM Setup"
Write-Host "================"

# Install certificate
Write-Host "Installing certificate..."
`$certSecurePassword = ConvertTo-SecureString `$CertPassword -AsPlainText -Force
Import-PfxCertificate -FilePath `$CertPath -CertStoreLocation Cert:\LocalMachine\Root -Password `$certSecurePassword -Exportable | Out-Null
Write-Host "✓ Certificate installed"

# Copy driver to System32\drivers
Write-Host "Installing driver..."
Copy-Item `$DriverPath -Destination "C:\Windows\System32\drivers\AvMiniFilter.sys" -Force
Write-Host "✓ Driver copied"

Write-Host "`nSetup complete! Driver is ready to load."
Write-Host "To load: net start AvMiniFilter"
"@

$setupScript | Out-File -FilePath "$VMPath\setup.ps1" -Encoding UTF8

Write-Host "`n✓ VM setup script created: $VMPath\setup.ps1"

Write-Host "`nDeployment files ready. In the VM, run as Administrator:"
Write-Host "  powershell.exe -ExecutionPolicy Bypass -File setup.ps1"
