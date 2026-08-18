@echo off
setlocal

set "ROOT=%~dp0"
cd /d "%ROOT%"

echo ============================================
echo   Gatekeeper - Demo Launcher
echo ============================================
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

echo [1/4] Building demo backend...
go build -o bin\demo-backend.exe .\scripts\demo-backend
if errorlevel 1 (
    echo [ERROR] Failed to build the demo backend.
    pause
    exit /b 1
)

echo [2/4] Building gatekeeper...
go build -o bin\gatekeeper.exe .\cmd\gatekeeper
if errorlevel 1 (
    echo [ERROR] Failed to build gatekeeper.
    pause
    exit /b 1
)

echo [3/4] Starting services...
start "Gatekeeper Demo Backend (port 9000)" cmd /k "bin\demo-backend.exe"
timeout /t 1 /nobreak >nul
start "Gatekeeper (port 8080)" cmd /k "bin\gatekeeper.exe -config configs\config.yaml -dashboard"
timeout /t 2 /nobreak >nul

echo [4/4] Opening dashboard in your browser...
start "" "http://localhost:8080/_dashboard"

echo.
echo Ready. Close the two console windows that opened when you're done testing.
echo.
pause
endlocal
