@echo off
REM AKAGAMI - Stop Services Script for Windows

echo.
echo ⚔️  AKAGAMI - Stopping Services
echo ==============================
echo.

docker-compose down

echo.
echo ✅ AKAGAMI services stopped
echo.
pause
