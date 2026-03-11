@echo off
setlocal

set VERSION=%~1
if "%VERSION%"=="" set VERSION=1.0.0
set SCRIPT_DIR=%~dp0
set ICON_PATH=%SCRIPT_DIR%assets\eyesandears.ico
set PYTHON_CMD=

pushd "%SCRIPT_DIR%.."

call :resolve_python
if errorlevel 1 goto :fail

echo [1/4] Installing build dependencies...
%PYTHON_CMD% -m pip install --upgrade pip
%PYTHON_CMD% -m pip install -r requirements.txt pyinstaller
if errorlevel 1 goto :fail

echo [2/4] Building single-file GUI EXE...
%PYTHON_CMD% -m PyInstaller --noconfirm --clean --onefile --windowed --icon "%ICON_PATH%" --name EyesAndEars "eyesandears.py"
if errorlevel 1 goto :fail

echo [3/4] Creating versioned release artifact...
copy /Y "dist\EyesAndEars.exe" "dist\EyesAndEars-%VERSION%-x64.exe" >nul
if errorlevel 1 goto :fail

echo [4/4] SHA256 (use this in winget installer manifest):
certutil -hashfile "dist\EyesAndEars-%VERSION%-x64.exe" SHA256

echo.
echo Build complete: dist\EyesAndEars-%VERSION%-x64.exe
popd
exit /b 0

:fail
popd
echo Build failed.
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
