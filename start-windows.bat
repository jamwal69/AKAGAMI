@echo off
REM AKAGAMI - Quick Start Script for Windows
REM Launch AKAGAMI services quickly

echo.
echo ⚔️  AKAGAMI - Quick Start
echo ========================
echo.

REM Check if Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not running
    echo Please start Docker Desktop and try again
    pause
    exit /b 1
)

echo [INFO] Starting AKAGAMI services...
docker-compose up -d

echo.
echo [INFO] Waiting for services...
timeout /t 5 /nobreak >nul

echo.
echo [INFO] Opening GUI...
start "" "file:///%CD%\akagami-red-gui.html"

echo.
echo ✅ AKAGAMI is running!
echo.
echo Quick access:
echo   GUI:     file:///%CD%\akagami-red-gui.html
echo   API:     http://localhost:8001
echo   Docs:    http://localhost:8001/docs
echo.
echo To stop: docker-compose down
pause
