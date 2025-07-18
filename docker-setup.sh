#!/bin/bash

# AKAGAMI Setup Script for Docker Deployment
# Automated setup for production deployment

set -e  # Exit on any error

echo "⚔️  AKAGAMI - Docker Deployment Setup"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Check if Docker is installed
check_docker() {
    print_step "Checking Docker installation..."
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
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
    
    if lsof -Pi :8001 -sTCP:LISTEN -t >/dev/null ; then
        print_warning "Port 8001 is already in use. Please stop the service or change the port."
    fi
    
    if lsof -Pi :3000 -sTCP:LISTEN -t >/dev/null ; then
        print_warning "Port 3000 is already in use. Frontend may not start properly."
    fi
}

# Build Docker images
build_images() {
    print_step "Building Docker images..."
    
    # Build the main application image
    docker build -t akagami:latest .
    
    print_status "Docker images built successfully ✓"
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
            print_error "Backend API failed to start within 30 seconds"
            exit 1
        fi
        sleep 1
    done
}

# Show service status
show_status() {
    print_step "Service Status:"
    docker-compose ps
    
    echo ""
    print_status "🎉 AKAGAMI is now running!"
    echo ""
    echo "Access points:"
    echo "  📱 GUI (HTML):     file://$(pwd)/akagami-red-gui.html"
    echo "  🌐 Backend API:    http://localhost:8001"
    echo "  📚 API Docs:       http://localhost:8001/docs"
    echo "  🔍 Health Check:   http://localhost:8001/health"
    echo ""
    echo "CLI Usage:"
    echo "  docker exec -it akagami-backend python backend/cli.py --help"
    echo "  docker exec -it akagami-backend python backend/cli.py cheats"
    echo ""
    echo "To stop services:"
    echo "  docker-compose down"
    echo ""
    echo "To view logs:"
    echo "  docker-compose logs -f"
}

# Main execution
main() {
    print_status "Starting AKAGAMI Docker setup..."
    
    check_docker
    setup_directories
    check_ports
    build_images
    start_services
    wait_for_services
    show_status
    
    print_status "Setup completed successfully! 🚀"
}

# Handle script interruption
trap 'print_error "Setup interrupted"; exit 1' INT

# Run main function
main
