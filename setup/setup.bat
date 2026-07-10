@echo off
REM TeoAvSuite Setup Script
REM Run as Administrator

title TeoAvSuite Installation

echo ===============================================
echo TeoAvSuite - Windows Kernel Security Research
echo ===============================================
echo.

REM Check if running as admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This installer requires Administrator privileges.
    echo Please run as Administrator.
    pause
    exit /b 1
)

echo Installing TeoAvSuite...
echo.

REM Create installation directory
set INSTALL_DIR=%ProgramFiles%\TeoAvSuite
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    echo Created: %INSTALL_DIR%
)

REM Copy files from current directory to installation directory
echo Copying application files...

REM Copy all exe files
copy /Y "*.exe" "%INSTALL_DIR%\" >nul 2>&1

REM Copy driver
copy /Y "*.sys" "%INSTALL_DIR%\" >nul 2>&1

REM Copy config
copy /Y "*.json" "%INSTALL_DIR%\" >nul 2>&1

REM Copy README
copy /Y "README.md" "%INSTALL_DIR%\" >nul 2>&1

if not exist "%INSTALL_DIR%\avdashboard.exe" (
    echo ERROR: Failed to copy files from: %CD%
    echo.
    echo Make sure all files are extracted from the ZIP:
    echo   - avdashboard.exe
    echo   - avconsolehost.exe
    echo   - avupdateserver.exe
    echo   - AvMiniFilter.sys
    echo   - avsuite.json
    echo   - README.md
    pause
    exit /b 1
)

echo.
echo ===============================================
echo Installation Complete!
echo ===============================================
echo.
echo Installation Directory: %INSTALL_DIR%
echo.
echo Next Steps:
echo 1. Read README.md for system requirements
echo 2. Follow driver setup instructions (test-signing, certificates)
echo 3. Run: %INSTALL_DIR%\avdashboard.exe
echo.
echo Documentation: https://github.com/teohumble1/avsuite
echo.
pause
