"""Kxstrel X MCP gateway package."""

__version__ = "2.1.0"

# Spectre version this gateway was built and verified against.
# spectre-mcp 1.0.3: FastMCP stdio server, ~104 tools, direct X GraphQL/REST,
# cookie auth (auth_token + ct0), deps limited to
# curl-cffi / fastmcp / loguru / pydantic / twscrape (no browser stack).
SPECTRE_PIN = "1.0.3"
