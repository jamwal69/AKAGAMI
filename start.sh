#!/bin/bash

# AKAGAMI - Quick Start Script for Linux/macOS
# Launch AKAGAMI services quickly

echo "⚔️  AKAGAMI - Quick Start"
echo "========================"
echo

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "[ERROR] Docker is not running"
    echo "Please start Docker and try again"
    exit 1
fi

echo "[INFO] Starting AKAGAMI services..."
docker-compose up -d

echo
echo "[INFO] Waiting for services..."
sleep 5

echo
echo "[INFO] Opening GUI..."
case "$OSTYPE" in
    darwin*)
        open "file://$(pwd)/akagami-red-gui.html"
        ;;
    linux*)
        if command -v xdg-open >/dev/null 2>&1; then
            xdg-open "file://$(pwd)/akagami-red-gui.html"
        else
            echo "Please open: file://$(pwd)/akagami-red-gui.html"
        fi
        ;;
esac

echo
echo "✅ AKAGAMI is running!"
echo
echo "Quick access:"
echo "  GUI:     file://$(pwd)/akagami-red-gui.html"
echo "  API:     http://localhost:8001"
echo "  Docs:    http://localhost:8001/docs"
echo
echo "To stop: docker-compose down"
