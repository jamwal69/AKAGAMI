from pydantic import BaseModel
from typing import List
import os

class Settings(BaseModel):
    app_name: str = "CyberSec Toolkit"
    version: str = "1.0.0"
    debug: bool = True
    
    # Database
    database_url: str = "sqlite:///./cybersec_toolkit.db"
    
    # Security
    secret_key: str = "your-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # API Keys (optional)
    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    
    # Rate limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 60

settings = Settings()
