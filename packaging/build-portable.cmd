@echo off
setlocal

set VERSION=%~1
if "%VERSION%"=="" set VERSION=1.0.0
set SCRIPT_DIR=%~dp0

pushd "%SCRIPT_DIR%.."

echo [1/4] Installing build dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt pyinstaller
if errorlevel 1 goto :fail

echo [2/4] Building single-file EXE...
pyinstaller --noconfirm --clean --onefile --name EyesAndEars "import os.py"
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
