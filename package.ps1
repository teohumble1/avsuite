# TeoAvSuite - Packaging script
# Run this BEFORE compiling the Inno Setup script.
# Creates a clean dist\ folder with only the files needed for installation.

$RelDir  = "$PSScriptRoot\build\release\src\dashboard_ui\RelWithDebInfo"
$AmsiDir = "$PSScriptRoot\build\release\src\amsi_provider\RelWithDebInfo"
$Dist    = "$PSScriptRoot\dist"

Write-Host "==> Cleaning dist folder..." -ForegroundColor Cyan
if (Test-Path $Dist) { Remove-Item $Dist -Recurse -Force }
New-Item -ItemType Directory $Dist | Out-Null
New-Item -ItemType Directory "$Dist\platforms"  | Out-Null
New-Item -ItemType Directory "$Dist\yara_rules" | Out-Null
New-Item -ItemType Directory "$Dist\quarantine" | Out-Null

Write-Host "==> Copying main exe..." -ForegroundColor Cyan
Copy-Item "$RelDir\avdashboard.exe" $Dist

Write-Host "==> Copying DLLs..." -ForegroundColor Cyan
Get-ChildItem "$RelDir\*.dll" | Copy-Item -Destination $Dist

Write-Host "==> Copying Qt platform plugin..." -ForegroundColor Cyan
Copy-Item "$RelDir\platforms\qwindows.dll" "$Dist\platforms\"

Write-Host "==> Copying YARA rules..." -ForegroundColor Cyan
Copy-Item "$RelDir\yara_rules\*" "$Dist\yara_rules\"

Write-Host "==> Copying AMSI provider..." -ForegroundColor Cyan
if (Test-Path "$AmsiDir\avamsi.dll") {
    Copy-Item "$AmsiDir\avamsi.dll" $Dist
} else {
    Write-Warning "avamsi.dll not found - AMSI integration will be skipped in installer."
}

$sizeMB = [math]::Round((Get-ChildItem $Dist -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
Write-Host "==> Done! dist\ folder ready: $sizeMB MB" -ForegroundColor Green
Write-Host "    Next: open installer.iss in Inno Setup and press Compile"
