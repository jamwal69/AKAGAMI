"""Nuclei tool definition — Template-based vulnerability scanner."""

NUCLEI_DEFINITION = {
    "name": "nuclei",
    "binary": "nuclei",
    "description": "Template-based vulnerability scanner",
    "opsec_risk": "medium",
    "active": True,
    "allowed_params": {
        "target": {"type": "string", "required": True},
        "templates": {"type": "string", "default": ""},
        "severity": {"type": "string", "default": "critical,high"},
        "output_json": {"type": "bool", "default": True},
    },
    "timeout": 600,
}
