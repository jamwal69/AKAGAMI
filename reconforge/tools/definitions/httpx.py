"""Httpx tool definition — HTTP probing and tech detection."""

HTTPX_DEFINITION = {
    "name": "httpx",
    "binary": "httpx-pd",
    "description": "HTTP probing, status codes, titles, tech detection",
    "opsec_risk": "low",
    "active": True,
    "allowed_params": {
        "target": {"type": "string", "required": True},
        "ports": {"type": "string", "default": "80,443,8080,8443"},
        "json_output": {"type": "bool", "default": True},
    },
    "timeout": 300,
}
