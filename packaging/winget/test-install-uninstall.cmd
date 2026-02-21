@echo off
setlocal

set SCRIPT_DIR=%~dp0
set MANIFEST_DIR=%SCRIPT_DIR%
set PACKAGE_ID=%~1
if "%PACKAGE_ID%"=="" set PACKAGE_ID=YourName.EyesAndEars

where winget >nul 2>nul
if errorlevel 1 (
  echo winget is not installed on this machine.
  exit /b 1
)

echo [1/4] Installing from local manifest...
winget install --manifest "%MANIFEST_DIR%" --accept-package-agreements --accept-source-agreements --silent
if errorlevel 1 goto :fail

echo [2/4] Verifying install...
winget list --id "%PACKAGE_ID%" --exact | findstr /i /c:"%PACKAGE_ID%" >nul
if errorlevel 1 (
  echo Package was not found after install.
  goto :fail
)

echo [3/4] Uninstalling with purge...
winget uninstall --id "%PACKAGE_ID%" --exact --purge --silent
if errorlevel 1 goto :fail

echo [4/4] Verifying uninstall...
winget list --id "%PACKAGE_ID%" --exact | findstr /i /c:"%PACKAGE_ID%" >nul
if not errorlevel 1 (
  echo Package still appears installed.
  goto :fail
)

echo Winget uninstall flow completed successfully.
exit /b 0

:fail
echo Winget install/uninstall flow failed.
exit /b 1
