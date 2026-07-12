@echo off
title SBOMGuard - restart
cd /d "%~dp0"

echo Stopping any SBOMGuard already running on port 8000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING') do (
    taskkill /F /PID %%a >nul 2>&1
)
timeout /t 2 /nobreak >nul
echo Done.
echo.

call "%~dp0start.bat"
