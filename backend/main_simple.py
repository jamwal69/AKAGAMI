from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import json
from modules.web_security import MODULES

app = FastAPI(
    title="Akagami - Advanced Cybersecurity Toolkit API",
    description="Advanced Penetration Testing Platform with Comprehensive Security Modules",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {
        "message": "⚔️ AKAGAMI - Advanced Cybersecurity Toolkit API v1.0.0",
        "status": "active",
        "modules": len(MODULES),
        "description": "Advanced Penetration Testing Platform",
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for Docker and monitoring"""
    return {"status": "healthy", "service": "AKAGAMI", "version": "1.0.0"}

@app.get("/api/health")
async def api_health_check():
    """Legacy health endpoint"""
    return {"status": "healthy", "version": "1.0.0"}

@app.get("/api/junior-pentest/modules")
async def list_modules():
    """List all available junior pentest modules"""
    modules_info = []
    for key, module in MODULES.items():
        modules_info.append({
            "id": key,
            "name": module.name,
            "description": module.description
        })
    return {"modules": modules_info}

@app.post("/api/junior-pentest/scan/{module_id}")
async def run_scan(module_id: str, target: str):
    """Run a specific security scan"""
    if module_id not in MODULES:
        return {"error": f"Module {module_id} not found"}
    
    module = MODULES[module_id]
    try:
        results = module.scan(target)
        return {"success": True, "results": results}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/junior-pentest/scan/{module_id}")
async def get_module_info(module_id: str):
    """Get information about a specific module"""
    if module_id not in MODULES:
        return {"error": f"Module {module_id} not found"}
    
    module = MODULES[module_id]
    return {
        "id": module_id,
        "name": module.name,
        "description": module.description
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
