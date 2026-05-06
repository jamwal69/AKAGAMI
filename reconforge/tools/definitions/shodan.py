"""Shodan tool definition — Infrastructure exposure lookup."""

SHODAN_DEFINITION = {
    "name": "shodan",
    "binary": None,  # MCP-based, no local binary
    "description": "Infrastructure exposure, open ports from Shodan's index",
    "opsec_risk": "passive",
    "active": False,
    "mcp": True,
    "allowed_params": {
        "target": {"type": "string", "required": True},
        "query": {"type": "string", "default": ""},
    },
    "timeout": 60,
}
