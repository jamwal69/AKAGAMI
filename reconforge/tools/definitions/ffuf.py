"""Ffuf tool definition — Directory and file fuzzer."""

FFUF_DEFINITION = {
    "name": "ffuf",
    "binary": "ffuf",
    "description": "Web directory and file fuzzer",
    "opsec_risk": "medium",
    "active": True,
    "allowed_params": {
        "url": {"type": "string", "required": True},
        "wordlist": {"type": "string", "required": True},
        "extensions": {"type": "string", "default": ""},
        "rate_limit": {"type": "int", "default": 0},
    },
    "timeout": 300,
}
