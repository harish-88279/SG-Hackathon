@echo off
title SBOMGuard - Software Supply Chain Risk Scorer
cd /d "%~dp0"

echo ======================================================================
echo   SBOMGuard - Software Supply Chain Risk Scorer
echo   Societe Generale hackathon, PB-10
echo ======================================================================
echo.

REM --- Find a Python interpreter -------------------------------------------
set PY=
where py >nul 2>&1 && set PY=py -3
if "%PY%"=="" (
    where python >nul 2>&1 && set PY=python
)
if "%PY%"=="" (
    echo ERROR: Python was not found on your PATH.
    echo Install Python 3.10+ from https://python.org and try again.
    echo.
    pause
    exit /b 1
)

echo Using: %PY%
%PY% --version
echo.

REM --- Install dependencies (quiet; skips anything already present) ---------
echo Installing dependencies...
%PY% -m pip install -q -r requirements.txt
if errorlevel 1 (
    echo.
    echo Dependency install failed. Trying with --user...
    %PY% -m pip install -q --user -r requirements.txt
)
echo Dependencies ready.
echo.

REM --- Generate the dataset if it is missing --------------------------------
if not exist "data\sample_data\sbom_dependencies.csv" (
    echo Generating the sample dataset...
    %PY% data\generator\generate_data.py
    echo.
)

REM --- Launch. run.py starts the server AND opens the browser. --------------
echo Starting SBOMGuard...
echo.
echo   Dashboard:  http://localhost:8000
echo   API docs:   http://localhost:8000/docs
echo.
echo   DEMO: type  CVE-2021-44228  into the War Room search box.
echo.
echo   Press Ctrl-C in this window to stop the server.
echo ======================================================================
echo.

%PY% run.py

echo.
echo Server stopped.
pause
