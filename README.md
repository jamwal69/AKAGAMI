# ⚔️ AKAGAMI - Advanced Cybersecurity Penetration Testing Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.8%2B-red)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-red)](https://github.com/yourusername/akagami)

**AKAGAMI** is a comprehensive, modular cybersecurity penetration testing toolkit designed for security professionals, researchers, and ethical hackers. Built with both CLI and GUI interfaces, it provides an organized approach to web application security testing.

## ⚠️ Legal Notice

**FOR AUTHORIZED TESTING ONLY!** This tool is intended for security professionals, penetration testers, and system administrators to test systems they own or have explicit written permission to test. Users are responsible for complying with all applicable laws and regulations.

## 🎯 Features

### 🔥 Current Modules (Stage 1)

#### Web Application Security Testing
- **Application Walking**: Systematically explore and map web application structure
- **Content Discovery**: Discover hidden files, directories, and endpoints
- **Subdomain Enumeration**: Find subdomains of target domains
- **Authentication Bypass**: Test for authentication bypass vulnerabilities
- **IDOR Testing**: Detect Insecure Direct Object Reference vulnerabilities
- **File Inclusion**: Test for Local and Remote File Inclusion vulnerabilities
- **SSRF Detection**: Server-Side Request Forgery vulnerability testing
- **XSS Scanning**: Cross-Site Scripting vulnerability detection
- **Race Conditions**: Test for race condition vulnerabilities
- **Command Injection**: Detect command injection vulnerabilities
- **SQL Injection**: Comprehensive SQL injection testing

## 🏗️ Architecture

- **Backend**: Python FastAPI with async support
- **Frontend**: React.js with TypeScript and Material-UI
- **CLI**: Rich terminal interface with Python Click
- **Database**: SQLite with async support
- **Modular Design**: Each security test is a separate, reusable module

## 📦 Installation

### Prerequisites
- Python 3.8+
- Node.js 16+
- npm or yarn
- Docker & Docker Compose (recommended)

### Quick Setup

#### Option 1: Docker (Recommended)
```bash
# Clone the repository
git clone https://github.com/yourusername/akagami.git
cd akagami

# Start with Docker Compose
docker-compose up -d

# Access GUI at http://localhost:3000
# Backend API at http://localhost:8001
# CLI access: docker exec -it akagami-backend python backend/cli.py --help
```

#### Option 2: Manual Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/akagami.git
cd akagami

# Run the setup script
python setup.py

# Or manual installation
pip install -r requirements.txt
cd frontend && npm install && cd ..
```

## 🖥️ Usage

### Web Interface (GUI)
```bash
# Start the full application
npm run dev

# Or start components separately
npm run backend    # Start API server
npm run frontend   # Start React app
```

Access the web interface at `http://localhost:3000`

### Command Line Interface (CLI)
```bash
cd backend

# Show help
python cli.py --help

# List available web security modules
python cli.py web list-modules

# Run application walking
python cli.py web app-walker https://example.com

# Run content discovery
python cli.py web content-discovery https://example.com

# Run subdomain enumeration
python cli.py web subdomain-enum example.com

# Run vulnerability scans
python cli.py web vuln-scan https://example.com --module xss
python cli.py web vuln-scan https://example.com --module sql-injection

# Run all vulnerability scans
python cli.py web vuln-scan https://example.com

# Start the API server
python cli.py server --host 0.0.0.0 --port 8000

# Launch GUI
python cli.py gui
```

### API Usage
```bash
# Start the API server
cd backend
python main.py
```

API documentation available at `http://localhost:8000/docs`

#### Example API Calls
```bash
# Get available modules
curl http://localhost:8000/api/junior-pentest/modules

# Run application walking
curl -X POST http://localhost:8000/api/junior-pentest/scan/app-walker \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

# Run XSS scan
curl -X POST http://localhost:8000/api/junior-pentest/scan/xss \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'
```

## 📁 Project Structure

```
akagami/
├── 🐳 Docker Configuration
│   ├── Dockerfile              # Multi-stage Docker build
│   ├── docker-compose.yml      # Service orchestration
│   ├── .dockerignore           # Docker build exclusions
│   └── docker-setup.sh         # Automated Docker setup
├── 🎮 GUI Interfaces  
│   ├── akagami-red-gui.html    # Professional red-themed GUI
│   ├── akagami-gui.html        # Alternative GUI interface
│   └── simple-gui.html         # Basic testing interface
├── ⚙️ Backend (Python FastAPI)
│   ├── main.py                 # Full FastAPI application
│   ├── main_simple.py          # Simplified API server
│   ├── cli.py                  # Rich CLI interface with cheats
│   ├── core/
│   │   ├── config.py           # Configuration management
│   │   └── database.py         # Database operations
│   ├── routers/
│   │   ├── auth.py             # Authentication endpoints
│   │   └── junior_pentest.py   # Security testing endpoints
│   ├── modules/
│   │   └── web_security.py     # Security testing modules
│   ├── logs/                   # Application logs
│   ├── reports/                # Scan reports
│   ├── uploads/                # File uploads
│   └── data/                   # Application data
├── 🌐 Frontend (React TypeScript)
│   ├── package.json            # Node.js dependencies
│   ├── tsconfig.json           # TypeScript configuration
│   ├── public/                 # Static assets
│   └── src/                    # React source code
├── 📄 Configuration
│   ├── requirements.txt        # Python dependencies
│   ├── package.json           # Node.js project config
│   ├── setup.py               # Setup script
│   ├── .gitignore             # Git exclusions
│   └── README.md              # This file
└── 🚀 Deployment
    ├── docker-setup.sh        # Docker deployment script
    └── .github/               # GitHub Actions (optional)
```

## 🔧 Configuration

### Environment Variables
Edit `.env` file to configure:

```env
SECRET_KEY=your-secret-key
DEBUG=True
DATABASE_URL=sqlite:///./cybersec_toolkit.db

# Optional API Keys
SHODAN_API_KEY=your-shodan-key
CENSYS_API_ID=your-censys-id
CENSYS_API_SECRET=your-censys-secret

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
```

## 🧪 Example Usage

### Testing a Web Application
```bash
# 1. Map the application
python cli.py web app-walker https://example.com

# 2. Discover hidden content
python cli.py web content-discovery https://example.com

# 3. Find subdomains
python cli.py web subdomain-enum example.com

# 4. Test for vulnerabilities
python cli.py web vuln-scan https://example.com --save results.json
```

### Sample Output
```json
{
  "target": "https://example.com",
  "vulnerabilities": [
    {
      "type": "Reflected XSS",
      "url": "https://example.com/search?q=<script>alert('XSS')</script>",
      "risk": "Medium",
      "description": "User input is reflected without proper sanitization"
    }
  ],
  "total_vulnerabilities": 1,
  "execution_time": 15.42,
  "status": "completed"
}
```

## 🔮 Roadmap

### Stage 2: Intermediate Testing (Coming Soon)
- Network scanning and enumeration
- Wireless security testing
- Mobile application security
- API security testing

### Stage 3: Advanced Testing (Coming Soon)
- Binary analysis and reverse engineering
- Cryptographic analysis
- Advanced persistent threat simulation
- Custom exploit development

### Stage 4: Reporting & Automation (Coming Soon)
- Automated report generation
- CI/CD integration
- Custom vulnerability databases
- Team collaboration features

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. The developers are not responsible for any misuse or damage caused by this tool. Users must ensure they have proper authorization before testing any systems.

## 🙏 Acknowledgments

- Thanks to the cybersecurity community for various testing methodologies
- Built with modern open-source technologies
- Inspired by various security testing frameworks

## 📞 Support

For questions, issues, or contributions:
- Create an issue on GitHub
- Check the documentation
- Review the CLI help: `python cli.py --help`

---

**Happy Testing! 🔒🚀**
