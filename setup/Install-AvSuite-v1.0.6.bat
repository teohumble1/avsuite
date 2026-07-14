@echo off
REM TeoAvSuite v1.0.6 Auto-Installer
REM Double-click để tự động giải nén + cài đặt

setlocal enabledelayedexpansion

cls
echo.
echo ========================================
echo  TeoAvSuite v1.0.6 Setup
echo ========================================
echo.

REM Check if ZIP exists
if not exist "%~dp0AvSuite-v1.0.6.zip" (
    echo Error: AvSuite-v1.0.6.zip not found in %~dp0
    echo.
    echo Make sure both files are in the same folder:
    echo  - Install-AvSuite-v1.0.6.bat (this file)
    echo  - AvSuite-v1.0.6.zip
    echo.
    pause
    exit /b 1
)

REM Extract to Program Files
set INSTALL_PATH=%ProgramFiles%\TeoAvSuite
if exist "%INSTALL_PATH%" (
    echo Backing up existing installation...
    for /f "tokens=2-4 delims=/ " %%a in ('date /t') do (set mydate=%%c%%a%%b)
    ren "%INSTALL_PATH%" "%INSTALL_PATH%.bak-!mydate!"
)

echo Creating %INSTALL_PATH%...
mkdir "%INSTALL_PATH%"

echo Extracting files...
powershell -Command "Expand-Archive -Path '%~dp0AvSuite-v1.0.6.zip' -DestinationPath '%INSTALL_PATH%' -Force" 2>nul

if errorlevel 1 (
    echo.
    echo Error: Extraction failed. PowerShell may not have permissions.
    echo Try running as Administrator.
    pause
    exit /b 1
)

echo Creating desktop shortcut...
powershell -Command ^
  "$shell = New-Object -ComObject WScript.Shell;" ^
  "$link = $shell.CreateShortcut(\"$env:USERPROFILE\Desktop\AvSuite.lnk\");" ^
  "$link.TargetPath = '%INSTALL_PATH%\avdashboard.exe';" ^
  "$link.WorkingDirectory = '%INSTALL_PATH%';" ^
  "$link.IconLocation = '%INSTALL_PATH%\avdashboard.exe,0';" ^
  "$link.Save()"

cls
echo.
echo ========================================
echo  ✅ Installation Complete!
echo ========================================
echo.
echo Location: %INSTALL_PATH%
echo Desktop shortcut: AvSuite.lnk
echo.
echo To launch: Double-click AvSuite.lnk
echo.
pause
