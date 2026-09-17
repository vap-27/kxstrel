"""Kxstrel X MCP gateway package."""

__version__ = "2.2.0"

# Spectre version this gateway was built and verified against.
# spectre-mcp 1.0.3: FastMCP stdio server, ~104 tools, direct X GraphQL/REST,
# cookie auth (auth_token + ct0), deps limited to
# curl-cffi / fastmcp / loguru / pydantic / twscrape (no browser stack).
SPECTRE_PIN = "1.0.3"

# PyMySQL >=1.2.1 removed escape_dict from converters, which aiomysql<=0.3.2 imports.
# Inject fallback so aiomysql imports safely under any PyMySQL release.
try:
    import pymysql.converters as _pm_conv
    if not hasattr(_pm_conv, "escape_dict"):
        def _escape_dict(val, charset=None, mapping=None):
            raise TypeError("dict can not be used as parameter")
        _pm_conv.escape_dict = _escape_dict
except Exception:
    pass

