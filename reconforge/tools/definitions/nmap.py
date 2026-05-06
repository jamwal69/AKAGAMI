"""Nmap tool definition — Network port scanner and service fingerprinter."""

NMAP_DEFINITION = {
    "name": "nmap",
    "binary": "nmap",
    "description": "Network port scanner and service fingerprinter",
    "opsec_risk": "medium",
    "active": True,
    "allowed_params": {
        "target": {"type": "string", "required": True},
        "ports": {"type": "string", "default": "1-65535"},
        "timing": {"type": "int", "default": 3, "opsec_override": 2},
        "flags": {"type": "list", "default": ["-sV", "-sC", "--open"]},
        "output_xml": {"type": "bool", "default": True},
    },
    "timeout": 600,
}
