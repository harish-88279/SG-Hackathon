@echo off
setlocal enabledelayedexpansion
title SBOMGuard - deploy to Hugging Face Spaces
cd /d "%~dp0"

echo ======================================================================
echo   Deploy SBOMGuard to a Hugging Face Space
echo ======================================================================
echo.
echo   ONE-TIME SETUP (do this first, in a browser):
echo.
echo     1. Sign in at  https://huggingface.co   (free, no credit card)
echo     2. Go to       https://huggingface.co/new-space
echo     3. Name it     sbomguard
echo        SDK         Docker    ^<-- IMPORTANT, not Gradio/Streamlit
echo        Hardware    CPU basic (free)
echo        Visibility  Public
echo     4. Create it. Leave the page open - you will need the URL.
echo.
echo     5. Make an access token with WRITE permission:
echo        https://huggingface.co/settings/tokens
echo        Git will ask for it as the PASSWORD when this script pushes.
echo        (Your username is your HF username. The token is the password.)
echo.
echo ----------------------------------------------------------------------
echo.

set /p HFUSER=Your Hugging Face username:
if "%HFUSER%"=="" ( echo No username given. Aborting. & pause & exit /b 1 )

set /p HFSPACE=Space name [sbomguard]:
if "%HFSPACE%"=="" set HFSPACE=sbomguard

set REMOTE=https://huggingface.co/spaces/%HFUSER%/%HFSPACE%
echo.
echo   Deploying to: %REMOTE%
echo.

REM ---------------------------------------------------------------------
REM  We do NOT push this repo directly. A Space needs a README.md carrying
REM  YAML front matter (sdk: docker, app_port: 7860), and GitHub renders
REM  that front matter as an ugly table. So we assemble a clean copy in a
REM  temp folder, swap in the Space's own README, and push THAT.
REM ---------------------------------------------------------------------
set STAGE=%TEMP%\sbomguard-hf
if exist "%STAGE%" rmdir /s /q "%STAGE%"
mkdir "%STAGE%"

echo Staging a clean copy of the committed tree...
git archive HEAD | tar -x -C "%STAGE%"
if errorlevel 1 (
    echo.
    echo ERROR: could not export the repo. Commit your changes first:
    echo     git add -A ^&^& git commit -m "..."
    pause
    exit /b 1
)

copy /y "deploy\huggingface\SPACE_README.md" "%STAGE%\README.md" >nul
echo Swapped in the Space README (the one with the Docker front matter).
echo.

pushd "%STAGE%"
git init -q -b main
git config user.name  "Harish HJ"
git config user.email "hjharish2005@gmail.com"
git add -A
git commit -q -m "SBOMGuard - software supply chain risk analyzer (SG GRC Hackathon, PB-10)"

echo Pushing to Hugging Face...
echo   Username: %HFUSER%
echo   Password: paste your HF ACCESS TOKEN (not your account password)
echo.
git push --force "%REMOTE%" main

if errorlevel 1 (
    echo.
    echo ======================================================================
    echo   PUSH FAILED
    echo ======================================================================
    echo   Most likely causes:
    echo     - The Space does not exist yet. Create it at
    echo         https://huggingface.co/new-space   (SDK must be Docker)
    echo     - You used your account password. It must be an ACCESS TOKEN
    echo       with WRITE permission, from
    echo         https://huggingface.co/settings/tokens
    echo.
    popd
    pause
    exit /b 1
)

popd
echo.
echo ======================================================================
echo   DEPLOYED
echo ======================================================================
echo.
echo   Build log:  %REMOTE%
echo   Live app:   https://%HFUSER%-%HFSPACE%.hf.space
echo.
echo   The first build takes 3-5 minutes (it installs scikit-learn).
echo   Watch the "Building" indicator on the Space page. When it says
echo   "Running", your link is live.
echo.
pause
