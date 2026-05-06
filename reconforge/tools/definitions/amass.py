"""Amass tool definition — Subdomain enumeration."""

AMASS_DEFINITION = {
    "name": "amass",
    "binary": "amass",
    "description": "Subdomain enumeration — passive and active modes",
    "opsec_risk": "passive",
    "active": False,
    "allowed_params": {
        "mode": {"type": "string", "choices": ["passive", "active"], "default": "passive"},
        "domain": {"type": "string", "required": True},
    },
    "timeout": 300,
}
