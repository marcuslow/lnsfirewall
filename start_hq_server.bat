@echo off
echo 🔥 Starting pfSense Firewall Management HQ Server...
echo.

REM Clean up any existing processes first
echo 🧹 Cleaning up existing processes...
taskkill /f /im ngrok.exe >nul 2>nul
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000') do taskkill /f /pid %%a >nul 2>nul
timeout /t 2 /nobreak >nul

REM Check if ngrok is installed
where ngrok >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ ngrok not found! Please install ngrok first.
    echo Download from: https://ngrok.com/download
    pause
    exit /b 1
)

REM Check if Python is installed
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Python not found! Please install Python first.
    pause
    exit /b 1
)

echo ✅ Starting ngrok tunnel...
echo 🌐 Public URL: https://lnsfirewall.ngrok.app/
echo.

REM Start ngrok in background and Python server in foreground
REM Option 1: Use config file (if ngrok.yml is configured)
REM start "ngrok" ngrok start lnsfirewall --config=ngrok.yml

REM Option 2: Use command line with basic settings (current)
start "ngrok" ngrok http 8000 --domain=lnsfirewall.ngrok.app

REM Wait a moment for ngrok to start
timeout /t 3 /nobreak >nul

echo ✅ Starting HQ HTTP/WebSocket Server on localhost:8000...
echo 🌐 Public HTTPS: https://lnsfirewall.ngrok.app/
echo 🔌 WebSocket endpoint: wss://lnsfirewall.ngrok.app/ws
echo 📡 HTTP API endpoints:
echo   - GET  /status
echo   - GET  /clients
echo   - POST /register
echo   - POST /heartbeat
echo   - POST /poll
echo   - POST /command
echo   - POST /response
echo.
echo Press Ctrl+C to stop both services

REM Start the HTTP server (this will run in foreground)
python -m uvicorn hq.http_server:app --host 0.0.0.0 --port 8000 --log-level info

echo.
echo 🛑 Server stopped. Cleaning up...

REM Kill ngrok when Python server stops
echo   Stopping ngrok tunnel...
taskkill /f /im ngrok.exe >nul 2>nul
if %errorlevel% equ 0 (
    echo   ✅ ngrok stopped
) else (
    echo   ⚠️ ngrok was not running
)

REM Kill any remaining processes on port 8000
echo   Cleaning up port 8000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000') do (
    taskkill /f /pid %%a >nul 2>nul
    if %errorlevel% equ 0 echo   ✅ Stopped process %%a
)

echo ✅ All services stopped.
pause