@echo off
:: AvMiniFilter install script -- run as Administrator in test VM
:: Requires: bcdedit /set testsigning on (already done if driver loaded before)

echo ===== AvMiniFilter Deploy =====
echo.

:: 1. Unload + delete old instance if exists
echo [1] Removing old driver (if any)...
fltmc unload AvMiniFilter >nul 2>&1
sc stop AvMiniFilter >nul 2>&1
sc delete AvMiniFilter >nul 2>&1
ping -n 2 127.0.0.1 >nul

:: 2. Copy .sys to drivers folder
echo [2] Copying AvMiniFilter.sys to System32\drivers...
copy /y AvMiniFilter.sys %SystemRoot%\System32\drivers\AvMiniFilter.sys
if errorlevel 1 (
    echo ERROR: copy failed. Are you running as Administrator?
    pause & exit /b 1
)

:: 3. Register service
echo [3] Registering service...
sc create AvMiniFilter ^
    type= filesys ^
    start= demand ^
    binPath= "%SystemRoot%\System32\drivers\AvMiniFilter.sys" ^
    group= "FSFilter Activity Monitor" ^
    DisplayName= "AvSuite MiniFilter"
if errorlevel 1 (
    echo ERROR: sc create failed.
    pause & exit /b 1
)

:: 4. Set minifilter altitude (required -- FltMgr uses this for load order)
echo [4] Writing altitude registry key...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AvMiniFilter\Instances" ^
    /v DefaultInstance /t REG_SZ /d "AvMiniFilter Instance" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AvMiniFilter\Instances\AvMiniFilter Instance" ^
    /v Altitude /t REG_SZ /d "385101" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AvMiniFilter\Instances\AvMiniFilter Instance" ^
    /v Flags /t REG_DWORD /d 0 /f

:: 5. Load driver
echo [5] Loading driver...
fltmc load AvMiniFilter
if errorlevel 1 (
    echo ERROR: fltmc load failed. Check Event Viewer ^> System for details.
    echo Hint: make sure test signing is on -- run: bcdedit /set testsigning on
    pause & exit /b 1
)

:: 6. Verify
echo.
echo [6] Loaded minifilters:
fltmc | findstr /i "avmini\|Name\|------"
echo.
echo SUCCESS! Driver loaded. Now run avdashboard.exe from the dashboard folder.
pause
