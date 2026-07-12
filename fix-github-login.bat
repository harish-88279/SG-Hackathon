@echo off
title SBOMGuard - reset the GitHub login
cd /d "%~dp0"

echo ======================================================================
echo   Forgetting the cached GitHub login
echo ======================================================================
echo.
echo   Use this only if a push failed with:
echo       "Permission to harish-88279/SG-Hackathon.git denied to harish-hj"
echo.
echo   That means Windows is handing git the wrong GitHub account. This
echo   clears it so you get asked again on the next push.
echo.
pause

(echo protocol=https& echo host=github.com& echo.) | git credential reject >nul 2>&1
cmdkey /delete:git:https://github.com >nul 2>&1
cmdkey /delete:LegacyGeneric:target=git:https://github.com >nul 2>&1

echo.
echo Cleared.
echo.
echo   Now run push.bat. A GitHub sign-in window will open.
echo   SIGN IN AS:  harish-88279   (NOT harish-hj)
echo.
echo   If it still hands over harish-hj, GitHub Desktop is re-supplying it:
echo       GitHub Desktop - File - Options - Accounts - Sign out
echo.
pause
