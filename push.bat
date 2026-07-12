@echo off
title SBOMGuard - push to GitHub
cd /d "%~dp0"

echo ======================================================================
echo   Pushing SBOMGuard to github.com/harish-88279/SG-Hackathon
echo ======================================================================
echo.

where git >nul 2>&1
if errorlevel 1 (
    echo ERROR: git is not on your PATH. Open "Git Bash" and run:
    echo     git push -u origin main
    pause
    exit /b 1
)

git config --local user.name "Harish HJ"
git config --local user.email "hjharish2005@gmail.com"

REM ---------------------------------------------------------------------
REM  This machine was signed in to GitHub as "harish-hj", which does not
REM  have write access to the harish-88279 repo. Forget that cached login
REM  so Git Credential Manager asks again and you can sign in as the
REM  account that owns the repo.
REM ---------------------------------------------------------------------
echo Clearing the cached GitHub login...
(echo protocol=https& echo host=github.com& echo.) | git credential reject >nul 2>&1
cmdkey /delete:git:https://github.com >nul 2>&1
cmdkey /delete:LegacyGeneric:target=git:https://github.com >nul 2>&1
echo Done.
echo.

echo ======================================================================
echo   SIGN IN AS:  harish-88279
echo   (NOT harish-hj - that account cannot write to this repo)
echo ======================================================================
echo.
echo A GitHub sign-in window will open now.
echo.

git --no-pager log --oneline -1
echo.
echo Pushing...
git push -u origin main

if errorlevel 1 (
    echo.
    echo ======================================================================
    echo   PUSH STILL FAILED
    echo ======================================================================
    echo   If it says "denied to harish-hj" again, GitHub Desktop is probably
    echo   re-supplying that account. Open GitHub Desktop:
    echo       File - Options - Accounts - Sign out
    echo   then sign in as harish-88279 and run this file again.
    echo.
) else (
    echo.
    echo ======================================================================
    echo   PUSHED
    echo   https://github.com/harish-88279/SG-Hackathon
    echo ======================================================================
    echo.
)
pause
