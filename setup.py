#!/usr/bin/env python3
"""
Setup script for CyberSec Toolkit
"""

import subprocess
import sys
import os

def install_python_packages():
    """Install Python dependencies"""
    print("🔧 Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Python dependencies installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing Python dependencies: {e}")
        return False
    return True

def install_node_packages():
    """Install Node.js dependencies"""
    print("🔧 Installing Node.js dependencies...")
    try:
        subprocess.check_call(["npm", "install"], cwd=".")
        if os.path.exists("frontend"):
            subprocess.check_call(["npm", "install"], cwd="frontend")
        print("✅ Node.js dependencies installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing Node.js dependencies: {e}")
        return False
    return True

def setup_environment():
    """Setup environment variables"""
    print("🔧 Setting up environment...")
    
    env_content = """# CyberSec Toolkit Environment Variables
SECRET_KEY=your-secret-key-change-in-production
DEBUG=True
DATABASE_URL=sqlite:///./cybersec_toolkit.db

# API Keys (Optional)
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
"""
    
    if not os.path.exists(".env"):
        with open(".env", "w") as f:
            f.write(env_content)
        print("✅ Environment file created!")
    else:
        print("ℹ️  Environment file already exists")

def create_directories():
    """Create necessary directories"""
    print("📁 Creating directories...")
    
    directories = [
        "backend/logs",
        "backend/data",
        "backend/uploads",
        "backend/reports"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    print("✅ Directories created!")

def main():
    """Main setup function"""
    print("🔒 CyberSec Toolkit Setup")
    print("=" * 40)
    
    # Check if we're in the right directory
    if not os.path.exists("requirements.txt"):
        print("❌ requirements.txt not found. Please run this script from the project root.")
        sys.exit(1)
    
    # Setup steps
    create_directories()
    setup_environment()
    
    if install_python_packages():
        print("✅ Python setup completed!")
    else:
        print("❌ Python setup failed!")
        sys.exit(1)
    
    if install_node_packages():
        print("✅ Node.js setup completed!")
    else:
        print("❌ Node.js setup failed!")
        sys.exit(1)
    
    print("\n🎉 Setup completed successfully!")
    print("\nNext steps:")
    print("1. Review the .env file and add your API keys if needed")
    print("2. Start the backend: cd backend && python main.py")
    print("3. Start the frontend: cd frontend && npm start")
    print("4. Or use the CLI: cd backend && python cli.py --help")
    print("\n⚠️  Remember: Use this tool only on systems you own or have permission to test!")

if __name__ == "__main__":
    main()
