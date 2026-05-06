#!/bin/bash
# ReconForge Dependencies Installer
# Run this script with sudo privileges if you want to install everything system-wide.

echo "[+] Updating apt repositories..."
sudo apt-get update

echo "\n[+] Installing system dependencies (nmap, whois, theharvester, ffuf, golang)..."
sudo apt-get install -y nmap whois theharvester ffuf golang-go wget unzip

# Remove the conflicting python httpx CLI if it exists so it doesn't shadow the ProjectDiscovery one
if [ -f "/usr/bin/httpx" ]; then
    echo "\n[+] Removing conflicting python httpx..."
    sudo apt-get remove -y httpx || true
fi

echo "\n[+] Setting up Go environment..."
# Ensure Go binaries go to a system-wide or user-wide path that is in PATH
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

echo "\n[+] Installing latest ProjectDiscovery & OWASP tools via Go..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/owasp-amass/amass/v4/...@master

echo "\n[+] Ensuring Go binary path is in your ~/.bashrc..."
if ! grep -q 'export PATH=$PATH:$HOME/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    echo "Added \$HOME/go/bin to ~/.bashrc"
fi

echo "\n[+] Installation complete! Please run 'source ~/.bashrc' in your terminal before running ReconForge."
