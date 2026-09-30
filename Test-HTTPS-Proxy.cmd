@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0tests\Test-ProxyMitm.ps1"
echo.
pause
