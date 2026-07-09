@echo off
:: Unload and remove AvMiniFilter -- run as Administrator
echo Unloading AvMiniFilter...
fltmc unload AvMiniFilter
sc stop AvMiniFilter
sc delete AvMiniFilter
del /f %SystemRoot%\System32\drivers\AvMiniFilter.sys
echo Done.
pause
