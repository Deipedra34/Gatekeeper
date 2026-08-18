@echo off
setlocal

set "ROOT=%~dp0"
cd /d "%ROOT%"

echo ============================================
echo   Gatekeeper
echo ============================================
echo.
echo This starts the real gatekeeper binary against configs\config.yaml.
echo Edit that file first so its routes point at your actual backend
echo services (see README.md). For a self-contained demo with a fake
echo backend and an interactive test dashboard instead, run
echo start-demo.bat.
echo.

where go >nul 2>nul
if errorlevel 1 (
    if exist "C:\Program Files\Go\bin\go.exe" (
        set "PATH=%PATH%;C:\Program Files\Go\bin"
    ) else (
        echo [ERROR] Go was not found. Install it from https://go.dev/dl/
        pause
        exit /b 1
    )
)

if not exist "bin" mkdir "bin"

echo [1/2] Building gatekeeper...
go build -o bin\gatekeeper.exe .\cmd\gatekeeper
if errorlevel 1 (
    echo [ERROR] Build failed.
    pause
    exit /b 1
)

echo [2/2] Starting gatekeeper on the address configured in configs\config.yaml...
echo Press Ctrl+C to stop.
echo.
bin\gatekeeper.exe -config configs\config.yaml

endlocal
