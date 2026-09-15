"""MCP client registry: real client identification from the wire.

Every MCP handshake carries clientInfo (name, version) — "hermes",
"openclaw", "mcp-remote", etc. This middleware records each initialize so
the admin dashboard can show which clients actually connect, when they were
first/last seen, and how many sessions they opened. No synthetic or guessed
data: if nobody connected, the registry is empty.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from .logging_setup import get_logger, sanitize_error

log = get_logger("kxstrel-x-mcp.clients")

# Test/diagnostic client names injected during verification — not real users.
_TEST_CLIENT_NAMES = frozenset({"diag", "final-check", "verify", "test", "opencode-test"})

# clientInfo.version is wire-controlled: cap the distinct versions tracked
# per client name so a client cannot grow registry memory without bound.
# Overflowing versions are counted, not stored.
MAX_VERSIONS_PER_CLIENT = 8
# Same class of bound for the number of distinct client names.
MAX_CLIENTS = 512


@dataclass
class ClientStats:
    name: str
    versions: dict[str, int] = field(default_factory=dict)
    version_overflow: int = 0
    handshakes: int = 0
    first_seen: str = ""
    last_seen: str = ""
    last_seen_monotonic: float = 0.0

    def record_version(self, version: str) -> None:
        if version in self.versions:
            self.versions[version] += 1
        elif len(self.versions) < MAX_VERSIONS_PER_CLIENT:
            self.versions[version] = 1
        else:
            # Distinct-version flood: count it, do not allocate a new key.
            self.version_overflow += 1


class ClientRegistryMiddleware(Middleware):
    def __init__(self):
        self._clients: dict[str, ClientStats] = {}

    async def on_initialize(self, context: MiddlewareContext, call_next: CallNext):
        from datetime import datetime, timezone

        try:
            params = getattr(context.message, "params", None)
            info = getattr(params, "client_info", None) if params else None
            name = (getattr(info, "name", None) or "unknown").strip()[:64]
            version = (getattr(info, "version", None) or "?").strip()[:32]
            now_iso = datetime.now(timezone.utc).isoformat()
            stats = self._clients.get(name)
            if stats is None:
                if len(self._clients) >= MAX_CLIENTS:
                    # Registry full: bound memory, do not allocate.
                    log.debug("client registry full; ignoring name=%s", name)
                    return await call_next(context)
                stats = ClientStats(name=name, first_seen=now_iso)
                self._clients[name] = stats
                log.info("mcp client connected name=%s version=%s", name, version)
            stats.handshakes += 1
            stats.record_version(version)
            stats.last_seen = now_iso
            stats.last_seen_monotonic = time.monotonic()
        except Exception as exc:
            log.debug("client registry capture failed: %s", sanitize_error(str(exc)))
        return await call_next(context)

    def snapshot(self, active_within_seconds: int = 900) -> list[dict]:
        now = time.monotonic()
        out = []
        for stats in sorted(self._clients.values(), key=lambda s: -s.last_seen_monotonic):
            if stats.name in _TEST_CLIENT_NAMES:
                continue
            out.append({
                "name": stats.name,
                "versions": stats.versions,
                "version_overflow": stats.version_overflow,
                "handshakes": stats.handshakes,
                "first_seen": stats.first_seen,
                "last_seen": stats.last_seen,
                "active": (now - stats.last_seen_monotonic) < active_within_seconds,
            })
        return out

    def client_count(self) -> int:
        return len(self._clients)


def attach(mcp) -> ClientRegistryMiddleware | None:
    """Attach exactly once; returns the registry for dashboard reads."""
    try:
        existing = getattr(mcp, "_kxstrel_client_registry", None)
        if existing is not None:
            return existing
        registry = ClientRegistryMiddleware()
        mcp.add_middleware(registry)
        mcp._kxstrel_client_registry = registry  # type: ignore[attr-defined]
        log.info("client registry middleware attached to spectre server")
        return registry
    except Exception as exc:
        log.warning("client registry attach failed: %s", sanitize_error(str(exc)))
        return None
