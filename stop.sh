#!/bin/bash

# AKAGAMI - Stop Services Script for Linux/macOS

echo "⚔️  AKAGAMI - Stopping Services"
echo "=============================="
echo

docker-compose down

echo
echo "✅ AKAGAMI services stopped"
