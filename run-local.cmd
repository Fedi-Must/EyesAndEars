@echo off
setlocal

set SCRIPT_DIR=%~dp0
set PYTHON_CMD=

pushd "%SCRIPT_DIR%"

call :resolve_python
if errorlevel 1 goto :fail

echo [1/3] Installing Python dependencies...
%PYTHON_CMD% -m pip install --upgrade pip
%PYTHON_CMD% -m pip install -r requirements.txt
if errorlevel 1 goto :fail

echo [2/3] Launching EyesAndEars...
%PYTHON_CMD% "import os.py"
if errorlevel 1 goto :fail

echo [3/3] Done.
popd
exit /b 0

:fail
popd
echo run-local failed.
exit /b 1

:resolve_python
where python >nul 2>nul
if not errorlevel 1 (
  set PYTHON_CMD=python
  goto :eof
)

where py >nul 2>nul
if not errorlevel 1 (
  set PYTHON_CMD=py -3
  goto :eof
)

where winget >nul 2>nul
if errorlevel 1 (
  echo Python not found and winget is unavailable.
  echo Install Python 3 manually and rerun this script.
  exit /b 1
)

echo Python not found. Installing Python 3.12 via winget...
winget install --id Python.Python.3.12 -e --accept-package-agreements --accept-source-agreements --silent
if errorlevel 1 (
  echo Python installation failed.
  exit /b 1
)

where python >nul 2>nul
if not errorlevel 1 (
  set PYTHON_CMD=python
  goto :eof
)

where py >nul 2>nul
if not errorlevel 1 (
  set PYTHON_CMD=py -3
  goto :eof
)

echo Python installed but not available in this shell yet.
echo Close and reopen terminal, then rerun this script.
exit /b 1
