# TeoAvSuite Installer Builder
# Requires: Inno Setup 6.x installed

param(
    [switch]$Rebuild = $false,
    [string]$InnoPath = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
)

Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "TeoAvSuite Installer Builder" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan

# Check Inno Setup
if (-not (Test-Path $InnoPath)) {
    $InnoPath = "C:\Program Files\Inno Setup 6\ISCC.exe"
}

if (-not (Test-Path $InnoPath)) {
    Write-Host "❌ Inno Setup not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Download from: https://jrsoftware.org/isdl.php" -ForegroundColor Yellow
    Write-Host "Then run this script again." -ForegroundColor Yellow
    exit 1
}

Write-Host "✓ Inno Setup found: $InnoPath" -ForegroundColor Green

# Clean output if rebuild requested
if ($Rebuild) {
    Write-Host ""
    Write-Host "Cleaning output directory..."
    Remove-Item ".\Output" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Cleaned"
}

# Create output directory
New-Item -ItemType Directory -Path ".\Output" -Force -ErrorAction SilentlyContinue | Out-Null

# Compile installer
Write-Host ""
Write-Host "Compiling installer..." -ForegroundColor Cyan
& $InnoPath "TeoAvSuite.iss"

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "✅ Build successful!" -ForegroundColor Green
    Write-Host ""

    $exe = Get-ChildItem ".\Output\*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($exe) {
        $size_mb = [math]::Round($exe.Length / 1MB, 2)
        Write-Host "Output file: $($exe.Name) ($size_mb MB)" -ForegroundColor Green
        Write-Host "Location: $(Resolve-Path $exe.FullName)" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "1. Test the installer on a clean VM"
    Write-Host "2. Upload to: https://github.com/teohumble1/avsuite/releases"
    Write-Host "3. Scan with VirusTotal: https://www.virustotal.com/"
} else {
    Write-Host ""
    Write-Host "❌ Build failed!" -ForegroundColor Red
    exit 1
}
