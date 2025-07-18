# AKAGAMI - Advanced Windows PowerShell Installation Script
# Advanced Cybersecurity Toolkit Setup for Windows with PowerShell

param(
    [switch]$SkipDocker,
    [switch]$Verbose,
    [switch]$CreateShortcuts
)

# Set execution policy for current session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Colors for output
$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"
$Blue = "Blue"
$Magenta = "Magenta"

function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor $Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Red
}

function Write-Step {
    param([string]$Message)
    Write-Host "[STEP] $Message" -ForegroundColor $Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Magenta
}

# Banner
Write-Host ""
Write-Host "================================" -ForegroundColor $Red
Write-Host "⚔️  AKAGAMI - Windows Setup" -ForegroundColor $Red
Write-Host "Advanced PowerShell Installer" -ForegroundColor $Red
Write-Host "================================" -ForegroundColor $Red
Write-Host ""

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "Running without administrator privileges. Some features may not work properly."
}

# Check Docker installation
Write-Step "Checking Docker installation..."

try {
    $dockerVersion = docker --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Docker found: $dockerVersion"
    } else {
        throw "Docker not found"
    }
} catch {
    if (-not $SkipDocker) {
        Write-Error "Docker is not installed or not in PATH"
        Write-Host "Please install Docker Desktop from: https://www.docker.com/products/docker-desktop" -ForegroundColor $Yellow
        Write-Host "Or run with -SkipDocker to skip Docker checks" -ForegroundColor $Yellow
        exit 1
    }
}

# Check Docker Compose
try {
    $composeVersion = docker-compose --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Docker Compose found: $composeVersion"
    } else {
        throw "Docker Compose not found"
    }
} catch {
    if (-not $SkipDocker) {
        Write-Error "Docker Compose is not installed"
        Write-Host "Please install Docker Compose or update Docker Desktop" -ForegroundColor $Yellow
        exit 1
    }
}

# Check if Docker is running
Write-Step "Checking if Docker is running..."
try {
    docker info 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Docker daemon is running ✓"
    } else {
        Write-Warning "Docker daemon is not running. Please start Docker Desktop."
    }
} catch {
    Write-Warning "Could not connect to Docker daemon"
}

# Create necessary directories
Write-Step "Creating directory structure..."
$directories = @(
    "backend\logs",
    "backend\reports", 
    "backend\uploads",
    "backend\data"
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        if ($Verbose) { Write-Host "Created: $dir" }
    }
}
Write-Status "Directories created ✓"

# Check port availability
Write-Step "Checking port availability..."
$ports = @(8001, 3000)
foreach ($port in $ports) {
    $connection = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($connection) {
        Write-Warning "Port $port is already in use"
    }
}

# Build Docker images
if (-not $SkipDocker) {
    Write-Step "Building AKAGAMI Docker images..."
    try {
        docker build -t akagami:latest . 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Docker image built successfully ✓"
        } else {
            throw "Failed to build Docker image"
        }
    } catch {
        Write-Error "Failed to build Docker image: $_"
        exit 1
    }

    # Start services
    Write-Step "Starting AKAGAMI services..."
    try {
        docker-compose up -d 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Services started ✓"
        } else {
            throw "Failed to start services"
        }
    } catch {
        Write-Error "Failed to start services: $_"
        exit 1
    }

    # Wait for services
    Write-Step "Waiting for services to be ready..."
    Start-Sleep -Seconds 10

    # Check backend health
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8001/health" -TimeoutSec 10 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Status "Backend API is ready ✓"
        } else {
            Write-Warning "Backend may still be starting..."
        }
    } catch {
        Write-Warning "Could not verify backend status"
    }
}

# Create desktop shortcuts
if ($CreateShortcuts) {
    Write-Step "Creating desktop shortcuts..."
    
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $currentPath = Get-Location
    
    # GUI shortcut
    $guiShortcut = Join-Path $desktopPath "AKAGAMI GUI.lnk"
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($guiShortcut)
    $Shortcut.TargetPath = "$currentPath\akagami-red-gui.html"
    $Shortcut.Description = "AKAGAMI Cybersecurity Toolkit GUI"
    $Shortcut.Save()
    
    # Start script shortcut
    $startShortcut = Join-Path $desktopPath "Start AKAGAMI.lnk"
    $Shortcut2 = $WshShell.CreateShortcut($startShortcut)
    $Shortcut2.TargetPath = "$currentPath\start-windows.bat"
    $Shortcut2.Description = "Start AKAGAMI Services"
    $Shortcut2.Save()
    
    Write-Status "Desktop shortcuts created ✓"
}

# Show service status
if (-not $SkipDocker) {
    Write-Step "Service Status:"
    docker-compose ps
}

# Success message
Write-Host ""
Write-Success "🎉 AKAGAMI installation completed!"
Write-Host ""
Write-Host "Access Points:" -ForegroundColor $Blue
Write-Host "  📱 GUI (HTML):     file:///$((Get-Location).Path.Replace('\', '/'))/akagami-red-gui.html"
Write-Host "  🌐 Backend API:    http://localhost:8001"
Write-Host "  📚 API Docs:       http://localhost:8001/docs"
Write-Host "  🔍 Health Check:   http://localhost:8001/health"
Write-Host ""
Write-Host "CLI Usage:" -ForegroundColor $Blue
Write-Host "  docker exec -it akagami-backend python backend/cli.py --help"
Write-Host "  docker exec -it akagami-backend python backend/cli.py cheats"
Write-Host ""
Write-Host "Management:" -ForegroundColor $Blue
Write-Host "  Start:  .\start-windows.bat"
Write-Host "  Stop:   .\stop-windows.bat"
Write-Host "  Logs:   docker-compose logs -f"
Write-Host ""

# Open GUI
$openGui = Read-Host "Open GUI in browser? (y/n)"
if ($openGui -eq 'y' -or $openGui -eq 'Y') {
    Start-Process "file:///$((Get-Location).Path.Replace('\', '/'))/akagami-red-gui.html"
}

Write-Host "Setup completed successfully! 🚀" -ForegroundColor $Magenta
