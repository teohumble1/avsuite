@echo off
:: ===========================================================================
:: AvMiniFilter -- ONE-TIME VM SETUP (run as Administrator, inside the test VM)
:: ===========================================================================
:: Only needed the first time on a fresh VM. After this + a reboot, use
:: install_driver.bat to (re)load the driver.
::
:: SAFETY: never run this on your real host. Test-signing + importing this
:: self-made cert lowers the machine's driver-signing security on purpose --
:: only acceptable on a disposable, snapshotted VM.
:: ===========================================================================

echo ===== AvMiniFilter VM setup =====
echo.

net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: run this as Administrator.
    pause & exit /b 1
)

echo [1] Importing test certificate into Trusted Root + Trusted Publisher...
certutil -addstore Root "%~dp0WDKTestCert.cer"
certutil -addstore TrustedPublisher "%~dp0WDKTestCert.cer"
if errorlevel 1 (
    echo ERROR: certutil failed. Is WDKTestCert.cer next to this script?
    pause & exit /b 1
)

echo.
echo [2] Enabling test signing (kernel accepts test-signed drivers)...
bcdedit /set testsigning on
if errorlevel 1 (
    echo ERROR: bcdedit failed. If Secure Boot is ON in the VM, disable it
    echo        in the VM firmware settings first -- testsigning cannot be
    echo        enabled while Secure Boot is active.
    pause & exit /b 1
)

echo.
echo ===========================================================================
echo  DONE. Now REBOOT the VM.
echo  After reboot you should see a "Test Mode" watermark bottom-right.
echo  Then run:  install_driver.bat
echo ===========================================================================
pause
