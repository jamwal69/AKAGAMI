#!/bin/bash

# AKAGAMI - Universal Installation Script
# Cross-platform setup for Linux and macOS

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

print_success() {
    echo -e "${PURPLE}[SUCCESS]${NC} $1"
}

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        print_status "Detected: Linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        print_status "Detected: macOS"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]]; then
        OS="windows"
        print_status "Detected: Windows (Cygwin/MSYS)"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
}

# Check Docker installation
check_docker() {
    print_step "Checking Docker installation..."
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed."
        case $OS in
            "linux")
                echo "Install Docker with:"
                echo "curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh"
                echo "sudo usermod -aG docker \$USER"
                ;;
            "macos")
                echo "Install Docker Desktop from: https://www.docker.com/products/docker-desktop"
                ;;
            "windows")
                echo "Install Docker Desktop from: https://www.docker.com/products/docker-desktop"
                ;;
        esac
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed."
        case $OS in
            "linux")
                echo "Install Docker Compose with:"
                echo "sudo curl -L \"https://github.com/docker/compose/releases/download/1.29.2/docker-compose-\$(uname -s)-\$(uname -m)\" -o /usr/local/bin/docker-compose"
                echo "sudo chmod +x /usr/local/bin/docker-compose"
                ;;
            *)
                echo "Update Docker Desktop to get Docker Compose"
                ;;
        esac
        exit 1
    fi
    
    print_status "Docker and Docker Compose are installed ✓"
}

# Create necessary directories
setup_directories() {
    print_step "Setting up directory structure..."
    
    mkdir -p backend/logs
    mkdir -p backend/reports
    mkdir -p backend/uploads
    mkdir -p backend/data
    
    print_status "Directories created ✓"
}

# Check if ports are available
check_ports() {
    print_step "Checking port availability..."
    
    case $OS in
        "linux")
            if ss -tulpn | grep :8001 > /dev/null 2>&1; then
                print_warning "Port 8001 is already in use"
            fi
            if ss -tulpn | grep :3000 > /dev/null 2>&1; then
                print_warning "Port 3000 is already in use"
            fi
            ;;
        "macos")
            if lsof -Pi :8001 -sTCP:LISTEN -t >/dev/null 2>&1; then
                print_warning "Port 8001 is already in use"
            fi
            if lsof -Pi :3000 -sTCP:LISTEN -t >/dev/null 2>&1; then
                print_warning "Port 3000 is already in use"
            fi
            ;;
    esac
}

# Build Docker images
build_images() {
    print_step "Building AKAGAMI Docker images..."
    
    docker build -t akagami:latest .
    
    print_status "Docker image built successfully ✓"
}

# Start services
start_services() {
    print_step "Starting AKAGAMI services..."
    
    # Start services in detached mode
    docker-compose up -d
    
    print_status "Services started ✓"
}

# Wait for services to be ready
wait_for_services() {
    print_step "Waiting for services to be ready..."
    
    # Wait for backend to be healthy
    echo "Waiting for backend API..."
    for i in {1..30}; do
        if curl -f http://localhost:8001/health &> /dev/null; then
            print_status "Backend API is ready ✓"
            break
        fi
        if [ $i -eq 30 ]; then
            print_warning "Backend API may still be starting..."
            break
        fi
        sleep 1
        echo -n "."
    done
    echo
}

# Show service status
show_status() {
    print_step "Service Status:"
    docker-compose ps
    
    echo
    print_success "🎉 AKAGAMI is now running!"
    echo
    echo "Access points:"
    echo "  📱 GUI (HTML):     file://$(pwd)/akagami-red-gui.html"
    echo "  🌐 Backend API:    http://localhost:8001"
    echo "  📚 API Docs:       http://localhost:8001/docs"
    echo "  🔍 Health Check:   http://localhost:8001/health"
    echo
    echo "CLI Usage:"
    echo "  docker exec -it akagami-backend python backend/cli.py --help"
    echo "  docker exec -it akagami-backend python backend/cli.py cheats"
    echo
    echo "Management Commands:"
    echo "  Stop services:     docker-compose down"
    echo "  View logs:         docker-compose logs -f"
    echo "  Restart services:  docker-compose restart"
    echo "  Update images:     docker-compose pull && docker-compose up -d"
    echo
}

# Open GUI in browser
open_gui() {
    print_step "Opening GUI in browser..."
    
    case $OS in
        "linux")
            if command -v xdg-open &> /dev/null; then
                xdg-open "file://$(pwd)/akagami-red-gui.html" &> /dev/null &
            elif command -v firefox &> /dev/null; then
                firefox "file://$(pwd)/akagami-red-gui.html" &> /dev/null &
            else
                print_warning "Please manually open: file://$(pwd)/akagami-red-gui.html"
            fi
            ;;
        "macos")
            open "file://$(pwd)/akagami-red-gui.html" &> /dev/null &
            ;;
    esac
}

# Create desktop shortcuts
create_shortcuts() {
    print_step "Creating shortcuts..."
    
    case $OS in
        "linux")
            # Create .desktop file for Linux
            cat > ~/.local/share/applications/akagami.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=AKAGAMI Cybersecurity Toolkit
Comment=Advanced Penetration Testing Toolkit
Exec=xdg-open file://$(pwd)/akagami-red-gui.html
Icon=$(pwd)/frontend/public/logo192.png
Terminal=false
Categories=Security;Development;
EOF
            print_status "Desktop shortcut created ✓"
            ;;
        "macos")
            # Create an alias/shortcut for macOS
            echo "alias akagami-gui='open file://$(pwd)/akagami-red-gui.html'" >> ~/.zshrc 2>/dev/null || echo "alias akagami-gui='open file://$(pwd)/akagami-red-gui.html'" >> ~/.bash_profile
            print_status "Shell alias created ✓"
            ;;
    esac
}

# Main execution
main() {
    echo
    echo "================================"
    echo "⚔️  AKAGAMI - Installation Setup"
    echo "================================"
    echo
    
    detect_os
    check_docker
    setup_directories
    check_ports
    build_images
    start_services
    wait_for_services
    show_status
    open_gui
    create_shortcuts
    
    echo
    print_success "Setup completed successfully! 🚀"
    echo
    echo "Next steps:"
    echo "1. The GUI should open automatically in your browser"
    echo "2. Try the CLI: docker exec -it akagami-backend python backend/cli.py cheats"
    echo "3. Read the documentation at: http://localhost:8001/docs"
    echo
}

# Handle script interruption
trap 'print_error "Setup interrupted"; exit 1' INT

# Run main function
main
