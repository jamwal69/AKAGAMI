# AKAGAMI Installation Guide

Welcome to AKAGAMI! This guide will help you install the Advanced Cybersecurity Toolkit on Windows, Linux, or macOS.

## 🚀 Quick Installation

### Windows Users

#### Option 1: Simple Batch Script (Recommended)
1. **Download/Clone AKAGAMI**
   ```cmd
   git clone https://github.com/yourusername/akagami.git
   cd akagami
   ```

2. **Run the installer**
   ```cmd
   install-windows.bat
   ```

3. **Start using AKAGAMI**
   ```cmd
   start-windows.bat
   ```

#### Option 2: Advanced PowerShell Script
1. **Open PowerShell as Administrator**
2. **Run the advanced installer**
   ```powershell
   .\install-windows.ps1 -CreateShortcuts
   ```

### Linux/macOS Users

1. **Download/Clone AKAGAMI**
   ```bash
   git clone https://github.com/yourusername/akagami.git
   cd akagami
   ```

2. **Run the installer**
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

3. **Start using AKAGAMI**
   ```bash
   ./start.sh
   ```

## 📋 Prerequisites

### All Platforms
- **Docker Desktop**: Download from [docker.com](https://www.docker.com/products/docker-desktop)
- **Git**: Download from [git-scm.com](https://git-scm.com/)

### Platform-Specific Requirements

#### Windows
- Windows 10/11 (64-bit)
- WSL2 enabled (for Docker Desktop)
- PowerShell 5.1+ (for advanced installer)

#### Linux
- Ubuntu 18.04+, CentOS 7+, or equivalent
- Docker and Docker Compose
- Bash shell

#### macOS
- macOS 10.15+ (Catalina or later)
- Docker Desktop for Mac
- Bash or Zsh shell

## 🛠️ Installation Scripts Overview

### Windows Scripts
- **`install-windows.bat`**: Simple GUI installer
- **`install-windows.ps1`**: Advanced PowerShell installer with shortcuts
- **`start-windows.bat`**: Quick start services
- **`stop-windows.bat`**: Stop all services

### Linux/macOS Scripts
- **`install.sh`**: Universal installer with OS detection
- **`start.sh`**: Quick start services
- **`stop.sh`**: Stop all services

### Docker Scripts
- **`docker-setup.sh`**: Advanced Docker deployment
- **`docker-compose.yml`**: Service orchestration

## 🚨 Troubleshooting

### Common Issues

#### Docker Not Running
**Windows**: Start Docker Desktop from the Start menu
**Linux**: `sudo systemctl start docker`
**macOS**: Start Docker Desktop from Applications

#### Port Already in Use
If ports 8001 or 3000 are in use:
```bash
# Stop conflicting services
docker-compose down

# Or change ports in docker-compose.yml
```

#### Permission Denied (Linux/macOS)
```bash
# Make scripts executable
chmod +x *.sh

# Add user to docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker
```

#### PowerShell Execution Policy (Windows)
```powershell
# Allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Getting Help

1. **Check service status**:
   ```bash
   docker-compose ps
   ```

2. **View logs**:
   ```bash
   docker-compose logs -f
   ```

3. **Restart services**:
   ```bash
   docker-compose restart
   ```

4. **Complete reset**:
   ```bash
   docker-compose down
   docker system prune -a
   # Then run installer again
   ```

## ⚡ Quick Commands

### Start AKAGAMI
```bash
# Windows
start-windows.bat

# Linux/macOS  
./start.sh

# Manual Docker
docker-compose up -d
```

### Stop AKAGAMI
```bash
# Windows
stop-windows.bat

# Linux/macOS
./stop.sh

# Manual Docker
docker-compose down
```

### Access Points
- **GUI**: `file:///path/to/akagami/akagami-red-gui.html`
- **API**: `http://localhost:8001`
- **Docs**: `http://localhost:8001/docs`
- **Health**: `http://localhost:8001/health`

### CLI Usage
```bash
# Show all commands
docker exec -it akagami-backend python backend/cli.py cheats

# Run security scan
docker exec -it akagami-backend python backend/cli.py web app-walker https://example.com
```

## 🔧 Advanced Configuration

### Custom Ports
Edit `docker-compose.yml`:
```yaml
ports:
  - "YOUR_PORT:8001"  # Change YOUR_PORT
```

### Persistent Data
Data is automatically persisted in:
- `backend/logs/` - Application logs
- `backend/reports/` - Scan reports  
- `backend/uploads/` - File uploads
- `backend/data/` - Application data

### Environment Variables
Create `.env` file:
```env
AKAGAMI_ENV=production
SECRET_KEY=your-secret-key
```

## 🎯 Next Steps

1. **Verify Installation**: Open `http://localhost:8001/health`
2. **Explore GUI**: Open the red-themed HTML interface
3. **Try CLI**: Run `docker exec -it akagami-backend python backend/cli.py cheats`
4. **Read Documentation**: Visit `http://localhost:8001/docs`
5. **Run First Scan**: Test with `https://httpbin.org` (safe testing site)

## ⚠️ Legal Notice

AKAGAMI is for authorized testing only. Ensure you have explicit permission before testing any systems. See `SECURITY.md` for responsible disclosure guidelines.

---

**Happy Hacking! 🚀⚔️**
