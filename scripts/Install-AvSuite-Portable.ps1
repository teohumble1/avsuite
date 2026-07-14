# TeoAvSuite v1.0.6 Portable Installer
# Usage: powershell -ExecutionPolicy Bypass -File Install-AvSuite-Portable.ps1

param(
    [string]$InstallPath = "$env:ProgramFiles\TeoAvSuite"
)

Write-Host "=== TeoAvSuite v1.0.6 Portable Installer ===" -ForegroundColor Cyan

# Check if running as admin
$isAdmin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "⚠ This installer requires Administrator privileges." -ForegroundColor Yellow
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
    exit 1
}

# Create installation directory
if (Test-Path $InstallPath) {
    Write-Host "⚠ $InstallPath already exists. Backing up..." -ForegroundColor Yellow
    Rename-Item $InstallPath "$InstallPath.bak-$(Get-Date -Format yyyyMMdd-HHmmss)" -Force
}

New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
Write-Host "✓ Created $InstallPath" -ForegroundColor Green

# Download latest release (you can customize this URL)
$releaseUrl = "https://github.com/teohumble1/avsuite/releases/download/v1.0.6/AvSuite-v1.0.6-portable.zip"
$zipPath = "$env:TEMP\AvSuite-v1.0.6.zip"

Write-Host "`nDownloading AvSuite v1.0.6..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $releaseUrl -OutFile $zipPath -ErrorAction Stop
    Write-Host "✓ Downloaded to $zipPath" -ForegroundColor Green
} catch {
    Write-Host "✗ Download failed: $_" -ForegroundColor Red
    exit 1
}

# Extract
Write-Host "Extracting files..."
Expand-Archive -Path $zipPath -DestinationPath $InstallPath -Force
Write-Host "✓ Extracted to $InstallPath" -ForegroundColor Green

# Create desktop shortcut
$shell = New-Object -ComObject WScript.Shell
$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcutPath = "$desktopPath\AvSuite.lnk"
$target = "$InstallPath\avdashboard.exe"

$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $target
$shortcut.WorkingDirectory = $InstallPath
$shortcut.IconLocation = "$target,0"
$shortcut.Save()
Write-Host "✓ Created desktop shortcut" -ForegroundColor Green

# Cleanup
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

Write-Host "`n=== Installation Complete ===" -ForegroundColor Green
Write-Host "Location: $InstallPath" -ForegroundColor Cyan
Write-Host "Desktop shortcut created" -ForegroundColor Cyan
Write-Host "`nTo launch: $InstallPath\avdashboard.exe" -ForegroundColor Yellow

# Optional: Launch now
$launch = Read-Host "Launch AvSuite now? (y/n)"
if ($launch -eq 'y') {
    & "$InstallPath\avdashboard.exe"
}
