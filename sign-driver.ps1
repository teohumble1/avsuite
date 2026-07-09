# Code-signing script for AvMiniFilter driver
param(
    [Parameter(Mandatory=$true)]
    [string]$DriverPath,

    [Parameter(Mandatory=$false)]
    [string]$CertPath = "D:\Dev\AvSuite\avsuite_driver_cert.pfx",

    [Parameter(Mandatory=$false)]
    [string]$CertPassword = "AvSuite2026"
)

$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"

if (-not (Test-Path $signtool)) {
    Write-Error "signtool.exe not found at: $signtool"
    exit 1
}

if (-not (Test-Path $DriverPath)) {
    Write-Error "Driver file not found: $DriverPath"
    exit 1
}

Write-Host "Signing driver: $DriverPath"
& $signtool sign /f $CertPath /p $CertPassword /fd sha256 /td sha256 /tr http://timestamp.digicert.com $DriverPath

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Driver signed successfully"
    exit 0
} else {
    Write-Error "Failed to sign driver"
    exit 1
}
