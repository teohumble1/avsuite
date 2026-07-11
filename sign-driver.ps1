# Code-signing script for AvMiniFilter driver
param(
    [Parameter(Mandatory=$true)]
    [string]$DriverPath,

    [Parameter(Mandatory=$false)]
    [string]$CertPath = "avsuite_cert.pfx"
)

# Prompt for password securely
Write-Host "Enter the certificate password (from generate-cert.ps1):"
$CertPassword = Read-Host -AsSecureString

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

# Convert SecureString to plaintext for signtool
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($CertPassword)
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($bstr)

& $signtool sign /f $CertPath /p $plainPassword /fd sha256 /td sha256 /tr http://timestamp.digicert.com $DriverPath

# Clear plaintext from memory
[System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($bstr)

if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Driver signed successfully"
    exit 0
} else {
    Write-Error "Failed to sign driver"
    exit 1
}
