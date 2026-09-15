"""Application-level authentication.

Remote MCP clients authenticate with a dedicated bearer token
(MCP_ACCESS_TOKEN). Admin credential-management endpoints use a separate
secret (ADMIN_TOKEN). X session cookies are NEVER accepted as client
credentials and are never exposed to clients.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request

from .config import Settings, get_settings

# --- advertised-origin validation -----------------------------------------
# The origin ends up inside a quoted auth-param in WWW-Authenticate:
#   Bearer error="invalid_token", resource_metadata="https://host/…"
# so a client-controlled host must never be able to terminate the quote or
# append another parameter — and must never point MCP clients at an
# attacker-chosen origin. Only a bare DNS name / IPv4 literal / bracketed
# IPv6 with an optional numeric port is accepted as a host; anything with a
# quote, comma, whitespace, control character, scheme, path or userinfo is
# refused outright (no "best effort" cleaning: a value that fails is dropped
# and the next, less client-controlled candidate is used).
_HOST_RE = re.compile(
    r"^(?:"
    r"[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?"  # DNS name or IPv4
    r"|\[[0-9A-Fa-f:.]{2,45}\]"                          # bracketed IPv6
    r")(?::([0-9]{1,5}))?$"
)
_ALLOWED_SCHEMES = ("http", "https")


def _safe_scheme(value: str | None) -> str | None:
    """Rightmost ``X-Forwarded-Proto`` entry (the trusted hop appends), or
    None unless it really is http/https."""
    scheme = (value or "").rsplit(",", 1)[-1].strip().lower()
    return scheme if scheme in _ALLOWED_SCHEMES else None


def _safe_host(value: str | None) -> str | None:
    """Return a syntactically valid ``host`` / ``host:port``, else None.

    No trimming: leading/trailing whitespace, CR/LF, NUL and every other
    control character must fail the match outright. Header values arrive
    already OWS-trimmed by the HTTP parser, and a value that needs repair is
    exactly the one that should not be trusted."""
    candidate = value or ""
    match = _HOST_RE.match(candidate)
    if not match:
        return None
    port = match.group(1)
    if port is not None and not 1 <= int(port) <= 65535:
        return None
    return candidate


def _forwarded_host(value: str | None) -> str | None:
    """Rightmost ``X-Forwarded-Host`` entry, validated.

    Each hop appends the host it received, so the rightmost element is the
    one added by the trusted edge in front of us — the same convention
    ``middleware._client_key`` applies to ``X-Forwarded-For``. Taking the
    leftmost element instead lets a caller prepend an arbitrary host and win
    (``X-Forwarded-Host: attacker.tld, real.internal``). Invalid entries are
    dropped rather than skipped backwards, which would fall back onto the
    caller's own text.

    Only spaces/tabs are trimmed around an element (the padding a comma list
    uses); CR, LF, NUL and friends are left in place so the validator rejects
    them instead of silently repairing the value into something valid."""
    return _safe_host((value or "").rsplit(",", 1)[-1].strip(" \t"))


def _safe_origin(value: str | None) -> str | None:
    """Validate a configured ``scheme://host[:port]`` origin (PUBLIC_BASE_URL)."""
    parts = urlsplit((value or "").strip())
    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        return None
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return None
    host = _safe_host(parts.netloc)
    if host is None:
        return None
    return f"{parts.scheme.lower()}://{host}"


def is_usable_origin(value: str) -> bool:
    """True when ``value`` is a bare http(s) origin (scheme + host[:port]).

    Startup validation for PUBLIC_BASE_URL: a value that fails this test is
    ignored at request time, so the process warns about it instead of
    silently advertising a derived origin."""
    return _safe_origin(value) is not None


def _resolve_settings(request: Request, settings: Settings | None) -> Settings:
    """Prefer the app instance's settings (tests, staging, multi-app hosts).

    A Request built straight from a scope — the unit-test path — has no ASGI
    ``app`` in scope, so the lookup falls back to the process settings
    instead of raising."""
    if settings is not None:
        return settings
    app = request.scope.get("app")
    return getattr(getattr(app, "state", None), "settings", None) or get_settings()


def external_base_url(request: Request, settings: Settings | None = None) -> str:
    """Absolute origin as seen by the client (edge-proxy aware).

    Precedence: PUBLIC_BASE_URL (authoritative when configured) > validated
    Host > validated X-Forwarded-Host > request netloc > localhost. Host is
    tried before X-Forwarded-Host because the edge routes on Host: a caller
    that only gets to add a header cannot move the advertised origin, and a
    list-valued X-Forwarded-Host still resolves to its rightmost (edge-added)
    element. Every candidate goes through ``_safe_host`` — neither header can
    inject a quote/comma/control character into the challenge, and a
    malformed value is dropped, not partially trusted.

    Without PUBLIC_BASE_URL a *well-formed* client-supplied Host is still
    echoed: HTTP provides no way to authenticate a Host header, so set
    PUBLIC_BASE_URL when the advertised origin must be trustworthy (it also
    covers the edge-rewrites-Host deployment where Host is an internal name).
    """
    settings = _resolve_settings(request, settings)
    origin = _safe_origin(settings.PUBLIC_BASE_URL)
    if origin:
        return origin
    scheme = (_safe_scheme(request.headers.get("x-forwarded-proto"))
              or _safe_scheme(request.url.scheme) or "http")
    for candidate in (_safe_host(request.headers.get("host")),
                      _forwarded_host(request.headers.get("x-forwarded-host")),
                      _safe_host(request.url.netloc)):
        if candidate:
            return f"{scheme}://{candidate}"
    return f"{scheme}://localhost"


def resource_metadata_url(request: Request, settings: Settings | None = None) -> str:
    """RFC 9728 protected-resource metadata URL advertised on MCP 401s.

    A spec-compliant client follows this instead of guessing, finds an empty
    `authorization_servers` list, and stops before attempting Dynamic Client
    Registration."""
    return (f"{external_base_url(request, settings)}"
            "/.well-known/oauth-protected-resource/mcp")


def _compare(a: str, b: str) -> bool:
    return bool(a and b) and hmac.compare_digest(a.encode(), b.encode())


def extract_bearer(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return ""
    return token.strip()


def token_fingerprint(token: str) -> str:
    """Short non-reversible caller identifier, safe for logs."""
    return hashlib.sha256(token.encode()).hexdigest()[:12]


def verify_mcp_token(request: Request, settings: Settings | None = None) -> str:
    # Dependencies must respect the app instance's settings. This matters for
    # tests, staging, and any process hosting more than one configured app.
    settings = _resolve_settings(request, settings)
    token = extract_bearer(request)
    if not settings.MCP_ACCESS_TOKEN:
        raise HTTPException(status_code=503, detail="service not configured (missing MCP token)")
    if not _compare(token, settings.MCP_ACCESS_TOKEN):
        raise HTTPException(
            status_code=401,
            detail="invalid or missing MCP access token",
            headers={"WWW-Authenticate": (
                'Bearer error="invalid_token", '
                f'resource_metadata="{resource_metadata_url(request, settings)}"')},
        )
    return token


def require_mcp(request: Request) -> str:
    return verify_mcp_token(request)


def require_admin(request: Request) -> str:
    settings = _resolve_settings(request, None)
    token = extract_bearer(request)
    if not settings.ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="admin endpoints are disabled (no ADMIN_TOKEN configured)")
    if not _compare(token, settings.ADMIN_TOKEN):
        raise HTTPException(
            status_code=401,
            detail="invalid or missing admin token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )
    return token


# Convenience FastAPI dependency aliases.
RequireMCP = Depends(require_mcp)
RequireAdmin = Depends(require_admin)
