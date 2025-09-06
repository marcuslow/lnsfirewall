@echo off
REM Make pfSense client bundle ZIP via PowerShell script
REM Usage: double-click this .bat or run from CMD

setlocal enabledelayedexpansion

REM Change to the directory of this script (repo root)
cd /d "%~dp0"

REM Check PowerShell availability
where powershell >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Windows PowerShell not found in PATH.
  echo Please run this from a system with PowerShell available, or run the PS1 manually.
  exit /b 1
)

set PS_CMD=powershell -ExecutionPolicy Bypass -File .\make_client_bundle.ps1 -OutputDir dist -BundleName pfsense-client-bundle

echo Running: %PS_CMD%
%PS_CMD%
set EXITCODE=%ERRORLEVEL%

if %EXITCODE% NEQ 0 (
  echo.
  echo [ERROR] Bundle creation failed with exit code %EXITCODE%.
  exit /b %EXITCODE%
)

echo.
echo [OK] Bundle created successfully. Check the dist\ folder for the ZIP.
exit /b 0

