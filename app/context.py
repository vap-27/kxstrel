"""ContextVar bridging HTTP-layer identity into the MCP tool-call layer.

The AuthMiddleware sets the MCP-token fingerprint per request; spectre's
FastMCP middleware (running in the same task tree) reads it so usage logs
can attribute calls to a caller without ever touching the raw token."""

from __future__ import annotations

from contextvars import ContextVar

caller_fp: ContextVar[str | None] = ContextVar("caller_fp", default=None)
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
