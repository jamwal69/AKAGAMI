@echo off
REM AKAGAMI - Windows Installation Script
REM Advanced Cybersecurity Toolkit Setup for Windows

echo.
echo ================================
echo ⚔️  AKAGAMI - Windows Setup
echo ================================
echo.

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not installed or not in PATH
    echo Please install Docker Desktop from: https://www.docker.com/products/docker-desktop
    echo.
    pause
    exit /b 1
)

REM Check if Docker Compose is installed
docker-compose --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker Compose is not installed
    echo Please install Docker Compose or update Docker Desktop
    echo.
    pause
    exit /b 1
)

echo [INFO] Docker and Docker Compose found ✓
echo.

REM Create necessary directories
echo [STEP] Creating directory structure...
if not exist "backend\logs" mkdir "backend\logs"
if not exist "backend\reports" mkdir "backend\reports"
if not exist "backend\uploads" mkdir "backend\uploads"
if not exist "backend\data" mkdir "backend\data"
echo [INFO] Directories created ✓
echo.

REM Check if ports are available
echo [STEP] Checking port availability...
netstat -an | find "8001" | find "LISTENING" >nul
if %errorlevel% equ 0 (
    echo [WARN] Port 8001 is already in use
)

netstat -an | find "3000" | find "LISTENING" >nul
if %errorlevel% equ 0 (
    echo [WARN] Port 3000 is already in use
)
echo.

REM Build Docker images
echo [STEP] Building AKAGAMI Docker images...
docker build -t akagami:latest .
if %errorlevel% neq 0 (
    echo [ERROR] Failed to build Docker image
    pause
    exit /b 1
)
echo [INFO] Docker image built successfully ✓
echo.

REM Start services
echo [STEP] Starting AKAGAMI services...
docker-compose up -d
if %errorlevel% neq 0 (
    echo [ERROR] Failed to start services
    pause
    exit /b 1
)
echo [INFO] Services started ✓
echo.

REM Wait for services to be ready
echo [STEP] Waiting for services to be ready...
timeout /t 10 /nobreak >nul

REM Check if backend is responding
curl -f http://localhost:8001/health >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] Backend API is ready ✓
) else (
    echo [WARN] Backend may still be starting...
)
echo.

REM Show status
echo [STEP] Checking service status...
docker-compose ps
echo.

echo ================================
echo 🎉 AKAGAMI is now running!
echo ================================
echo.
echo Access points:
echo   📱 GUI (HTML):     file:///%CD%\akagami-red-gui.html
echo   🌐 Backend API:    http://localhost:8001
echo   📚 API Docs:       http://localhost:8001/docs
echo   🔍 Health Check:   http://localhost:8001/health
echo.
echo CLI Usage:
echo   docker exec -it akagami-backend python backend/cli.py --help
echo   docker exec -it akagami-backend python backend/cli.py cheats
echo.
echo Management:
echo   To stop services:  docker-compose down
echo   To view logs:      docker-compose logs -f
echo   To restart:        docker-compose restart
echo.
echo Opening GUI in browser...
start "" "file:///%CD%\akagami-red-gui.html"
echo.
echo Setup completed successfully! 🚀
pause
