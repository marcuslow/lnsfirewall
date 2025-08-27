@echo off
echo 🔥 Starting pfSense Firewall Management HQ Server...
echo.

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
start "ngrok" ngrok http 8000 --domain=lnsfirewall.ngrok.app

REM Wait a moment for ngrok to start
timeout /t 3 /nobreak >nul

echo ✅ Starting HQ HTTP Server on localhost:8000...
echo 🌐 Public HTTPS: https://lnsfirewall.ngrok.app/
echo 📡 HTTP API endpoints:
"  - GET  /status"
"  - GET  /clients"
"  - POST /register\t{client_id, client_name?, hostname?}"
"  - POST /heartbeat\t{client_id}"
"  - POST /poll\t\t{client_id}"
"  - POST /command\t{client_id, command_type, params?}"
"  - POST /response\t{client_id, command_id?, data}"
echo.
echo Press Ctrl+C to stop both services

REM Start the HTTP server (this will run in foreground)
python -m uvicorn hq.http_server:app --host 0.0.0.0 --port 8000 --log-level info

echo.
echo 🛑 Server stopped. Cleaning up...

REM Kill ngrok when Python server stops
taskkill /f /im ngrok.exe >nul 2>nul

echo ✅ All services stopped.
pause