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

REM Copy Release files
echo Copying application files...
xcopy /Y /E "release\*" "%INSTALL_DIR%\" >nul 2>&1

if errorlevel 1 (
    echo ERROR: Failed to copy files
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
