#!/bin/bash
# ============================================================
#   AKAGAMI — External Tool Installer (Ubuntu/Debian/Kali)
#   Installs every reconnaissance tool that Akagami depends on.
#   Run with: bash install_tools.sh
# ============================================================
set -e

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
DIM='\033[2m'
NC='\033[0m' # No Color

echo -e "${RED}"
echo '    ___    __ __    ___    ____    ___    __  ___ ____'
echo '   /   |  / //_/  /   |  / ___/  /   |  /  |/  //  _/'
echo '  / /| | / ,<    / /| | / / _   / /| | / /|_/ / / /  '
echo ' / ___ |/ /| |  / ___ |/ /_/ / / ___ |/ /  / /_/ /   '
echo '/_/  |_/_/ |_| /_/  |_|\____/ /_/  |_/_/  /_//___/   '
echo -e "${NC}"
echo -e "${RED}⚔️  Tool Installer${NC}"
echo ""

# ── Helper ────────────────────────────────────────────────────
installed() { command -v "$1" &>/dev/null; }

check() {
    if installed "$1"; then
        echo -e "  ${GREEN}✓${NC} $1 $(command -v $1)"
    else
        echo -e "  ${RED}✗${NC} $1 — NOT FOUND"
        return 1
    fi
}

# ── 1. System packages ───────────────────────────────────────
echo -e "${YELLOW}[1/5]${NC} Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y -qq nmap whois golang-go wget unzip git curl > /dev/null 2>&1
echo -e "  ${GREEN}✓${NC} nmap, whois, golang, wget, unzip, git, curl"

# ── 2. theHarvester ──────────────────────────────────────────
echo -e "${YELLOW}[2/5]${NC} Installing theHarvester..."
if installed theharvester; then
    echo -e "  ${GREEN}✓${NC} theHarvester already installed"
else
    sudo apt-get install -y -qq theharvester > /dev/null 2>&1 && \
        echo -e "  ${GREEN}✓${NC} theHarvester installed via apt" || \
        echo -e "  ${YELLOW}⚠${NC} theHarvester not in apt — install manually: pip install theHarvester"
fi

# ── 3. Go-based tools (httpx, nuclei, ffuf, amass, trufflehog) ──────────
echo -e "${YELLOW}[3/5]${NC} Installing Go-based tools..."
mkdir -p ~/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

echo -e "  ${DIM}Installing httpx...${NC}"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null
echo -e "  ${GREEN}✓${NC} httpx"

echo -e "  ${DIM}Installing nuclei...${NC}"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null
echo -e "  ${GREEN}✓${NC} nuclei"

echo -e "  ${DIM}Installing ffuf...${NC}"
go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null
echo -e "  ${GREEN}✓${NC} ffuf"

echo -e "  ${DIM}Installing amass...${NC}"
go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null
echo -e "  ${GREEN}✓${NC} amass"

echo -e "  ${DIM}Installing trufflehog...${NC}"
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b ~/go/bin 2>/dev/null
echo -e "  ${GREEN}✓${NC} trufflehog"

# ── 4. searchsploit (exploitdb) ──────────────────────────────
echo -e "${YELLOW}[4/5]${NC} Installing searchsploit..."
if installed searchsploit; then
    echo -e "  ${GREEN}✓${NC} searchsploit already installed"
else
    # Try apt first (works on Kali), then fallback to git clone
    if sudo apt-get install -y -qq exploitdb > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} searchsploit installed via apt (exploitdb)"
    else
        echo -e "  ${DIM}apt failed, cloning from GitHub...${NC}"
        EXPLOIT_DIR="$HOME/exploitdb"
        if [ ! -d "$EXPLOIT_DIR" ]; then
            git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git "$EXPLOIT_DIR"
        fi
        if [ ! -L "/usr/local/bin/searchsploit" ]; then
            sudo ln -sf "$EXPLOIT_DIR/searchsploit" /usr/local/bin/searchsploit
        fi
        echo -e "  ${GREEN}✓${NC} searchsploit installed from GitLab"
    fi
fi

# ── 5. Python/Bug Bounty Tools ───────────────────────────────
echo -e "${YELLOW}[5/5]${NC} Installing Bug Bounty tools..."
pip3 install arjun clairvoyance > /dev/null 2>&1
echo -e "  ${GREEN}✓${NC} arjun, clairvoyance"

BB_DIR="$HOME/bugbounty_tools"
mkdir -p "$BB_DIR"

if [ ! -d "$BB_DIR/Corsy" ]; then
    git clone https://github.com/s0md3v/Corsy.git "$BB_DIR/Corsy" > /dev/null 2>&1
    sudo ln -sf "$BB_DIR/Corsy/corsy.py" /usr/local/bin/corsy
    chmod +x "$BB_DIR/Corsy/corsy.py"
fi
echo -e "  ${GREEN}✓${NC} corsy"

if [ ! -d "$BB_DIR/jwt_tool" ]; then
    git clone https://github.com/ticarpi/jwt_tool "$BB_DIR/jwt_tool" > /dev/null 2>&1
    pip3 install -r "$BB_DIR/jwt_tool/requirements.txt" > /dev/null 2>&1
    sudo ln -sf "$BB_DIR/jwt_tool/jwt_tool.py" /usr/local/bin/jwt_tool
    chmod +x "$BB_DIR/jwt_tool/jwt_tool.py"
fi
echo -e "  ${GREEN}✓${NC} jwt_tool"

if [ ! -d "$BB_DIR/graphql-cop" ]; then
    git clone https://github.com/doyensec/graphql-cop.git "$BB_DIR/graphql-cop" > /dev/null 2>&1
    pip3 install -r "$BB_DIR/graphql-cop/requirements.txt" > /dev/null 2>&1
    sudo ln -sf "$BB_DIR/graphql-cop/graphql-cop.py" /usr/local/bin/graphql-cop
    chmod +x "$BB_DIR/graphql-cop/graphql-cop.py"
fi
echo -e "  ${GREEN}✓${NC} graphql-cop"

if [ ! -d "$BB_DIR/SSRFmap" ]; then
    git clone https://github.com/swisskyrepo/SSRFmap "$BB_DIR/SSRFmap" > /dev/null 2>&1
    pip3 install -r "$BB_DIR/SSRFmap/requirements.txt" > /dev/null 2>&1
    sudo ln -sf "$BB_DIR/SSRFmap/ssrfmap.py" /usr/local/bin/ssrfmap
    chmod +x "$BB_DIR/SSRFmap/ssrfmap.py"
fi
echo -e "  ${GREEN}✓${NC} ssrfmap"

# ── Add Go bin to PATH permanently ───────────────────────────
if ! grep -q 'export PATH=$PATH:$HOME/go/bin' ~/.bashrc 2>/dev/null; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    echo -e "\n${DIM}Added \$HOME/go/bin to ~/.bashrc${NC}"
fi

# ── Final status check ───────────────────────────────────────
echo ""
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}  AKAGAMI — Tool Status${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

ALL_GOOD=true
for tool in nmap whois theharvester httpx nuclei ffuf amass searchsploit trufflehog arjun corsy jwt_tool graphql-cop clairvoyance ssrfmap; do
    check "$tool" || ALL_GOOD=false
done

echo ""
if $ALL_GOOD; then
    echo -e "${GREEN}All tools installed successfully! ⚔️${NC}"
else
    echo -e "${YELLOW}Some tools are missing. Check above and install manually.${NC}"
fi

echo -e "\n${DIM}Run 'source ~/.bashrc' or restart your terminal to pick up Go path changes.${NC}"
echo -e "${DIM}Then install Python deps: pip install -e .${NC}"
