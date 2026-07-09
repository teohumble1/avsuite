@echo off
REM Run as Administrator to install AvSuite driver

title AvSuite Driver Installation

if not "%1"=="am_admin" (
    powershell -Command "Start-Process cmd -ArgumentList '/c %~s0 am_admin' -Verb RunAs"
    exit /b
)

cls
echo.
echo ===============================
echo AvSuite Driver Setup
echo ===============================
echo.

REM Install certificate to Trusted Root
echo [1/3] Installing certificate...
powershell -Command "$cert = Import-PfxCertificate -FilePath '%~dp0avsuite_driver_cert.pfx' -CertStoreLocation Cert:\LocalMachine\Root -Password (ConvertTo-SecureString 'AvSuite2026' -AsPlainText -Force) -Exportable; Write-Host 'Certificate installed: ' $cert.Thumbprint"

REM Copy driver to System32
echo [2/3] Installing driver...
copy "%~dp0AvMiniFilter.sys" "C:\Windows\System32\drivers\AvMiniFilter.sys" /Y
if %errorlevel% equ 0 (
    echo Driver copied successfully
) else (
    echo ERROR: Failed to copy driver
    pause
    exit /b 1
)

REM Create service
echo [3/3] Creating service...
sc query AvMiniFilter >nul 2>&1
if errorlevel 1 (
    sc create AvMiniFilter binPath= "C:\Windows\System32\drivers\AvMiniFilter.sys" type= kernel
    echo Service created
) else (
    echo Service already exists
)

echo.
echo ===============================
echo Setup Complete!
echo ===============================
echo.
echo Next steps:
echo   net start AvMiniFilter
echo   fltmc instances
echo.
pause
