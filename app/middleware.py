"""HTTP middleware: request IDs, size limits, auth gating, rate limiting,
security headers, metrics."""

from __future__ import annotations

import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import metrics_setup
from .config import Settings
from .context import caller_fp as caller_fp_var
from .context import request_id_var
from .logging_setup import get_logger
from .rate_limit import RateLimiter
from .security import (extract_bearer, external_base_url, resource_metadata_url,
                       token_fingerprint)

log = get_logger("kxstrel-x-mcp.http")

# Paths served without a bearer token (login page / assets / login API).
# Everything else under /admin needs an admin session cookie or bearer.
# The login/session API routes are matched EXACTLY: prefix-matching them
# would make /admin/api/loginSteal and /admin/api/sessionSteal public too.
ADMIN_PUBLIC_PATHS = ("/admin", "/admin/")
ADMIN_PUBLIC_EXACT = ("/admin/api/login", "/admin/api/session")
ADMIN_PUBLIC_PREFIXES = ("/admin/assets/",)

# Console static assets deliberately get NO rate limiter: the /admin budget
# exists to slow credential guessing and API abuse, while a browser fetches
# these on every page load (HTML + CSS + JS) and again on every hard refresh.
# Sharing the budget meant a handful of reloads answered /admin/assets/* with
# the 429 JSON body, which the browser painted as the stylesheet/script — a
# blank, unstyled console. The files are public and credential-free, so there
# is nothing here to brute-force. Keep equal to ADMIN_PUBLIC_PREFIXES (the
# exemption is exactly the public-by-design asset family; asserted in tests).
ADMIN_ASSET_PREFIXES = ("/admin/assets/",)

# Abuse-protected metadata endpoints (they require auth themselves, but the
# rate budget must not depend on that).
META_ENDPOINTS = ("/tools", "/diagnostics", "/metrics")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
        "frame-ancestors 'none'"
    ),
}

# Fixed label set for the HTTP request counter: never label with the raw
# path (unauthenticated 404s would create unbounded time series).
_PATH_BUCKETS = ("/mcp", "/mcp/", "/health", "/status", "/tools",
                 "/diagnostics", "/metrics",
                 "/.well-known/oauth-protected-resource",
                 "/.well-known/oauth-protected-resource/mcp",
                 "/.well-known/oauth-authorization-server",
                 "/register", "/authorize", "/token")

# Every label _canonical_path may return (kept explicit so tests can assert
# against it without duplicating the mapping).
_PATH_LABELS = (frozenset(_PATH_BUCKETS) - {"/mcp/"}) | {
    "/admin", "/admin/api", "/admin/assets", "/.well-known", "other",
}


def _canonical_path(path: str) -> str:
    if path in _PATH_BUCKETS:
        # AuthMiddleware rewrites exact /mcp to /mcp/ internally; the two
        # share one metric label so the series never doubles.
        return "/mcp" if path == "/mcp/" else path
    if path.startswith("/.well-known/"):
        return "/.well-known"
    if path.startswith("/admin/assets/"):
        return "/admin/assets"
    if path.startswith("/admin/api/"):
        return "/admin/api"
    if path.startswith("/admin"):
        return "/admin"
    return "other"


def _client_key(request: Request) -> str:
    # Rightmost XFF entry is appended by the trusted edge proxy (Render);
    # the leftmost is client-controlled and would let callers rotate
    # rate-limit buckets at will.
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        candidate = forwarded.split(",")[-1].strip()
        if candidate:
            return candidate
    return request.client.host if request.client else "unknown"


def client_key(request: Request) -> str:
    """Rate-limit/audit caller key (public alias: routes need it for audit)."""
    return _client_key(request)


def _path_matches_public(path: str) -> bool:
    if path in ADMIN_PUBLIC_PATHS or path in ADMIN_PUBLIC_EXACT:
        return True
    return any(path.startswith(p) for p in ADMIN_PUBLIC_PREFIXES)


def _is_admin_asset(path: str) -> bool:
    return any(path.startswith(p) for p in ADMIN_ASSET_PREFIXES)


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or ""
        if not _REQUEST_ID_RE.match(request_id):
            request_id = uuid.uuid4().hex[:16]
        request.state.request_id = request_id
        token = request_id_var.set(request_id)
        started = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            log.exception("unhandled error request_id=%s path=%s", request_id, request.url.path)
            response = JSONResponse(
                {"error": {"code": "internal_error", "message": "Internal server error",
                           "request_id": request_id}},
                status_code=500,
            )
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = request_id
        elapsed_ms = (time.monotonic() - started) * 1000
        # Safe access log: method/path/status only, never headers or bodies.
        log.info("%s %s -> %s (%.1fms) rid=%s", request.method, request.url.path,
                 response.status_code, elapsed_ms, request_id)
        metrics_setup.http_requests_total.labels(
            path=_canonical_path(request.url.path), status=str(response.status_code)
        ).inc()
        if request.url.path.startswith("/admin"):
            for key, value in SECURITY_HEADERS.items():
                response.headers.setdefault(key, value)
        else:
            # Global minimum hardening for non-admin surfaces too.
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_bytes: int):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        length = request.headers.get("content-length")
        encoding = request.headers.get("transfer-encoding", "")
        if length and length.isdigit() and int(length) > self.max_bytes:
            return JSONResponse(
                {"error": {"code": "payload_too_large",
                           "message": f"Request body exceeds {self.max_bytes} bytes"}},
                status_code=413,
            )
        if "chunked" in encoding.lower() and not (length and length.isdigit()):
            # No legitimate chunked use in this app (JSON bodies always carry
            # Content-Length); reject to prevent unbounded streaming bodies
            # on the unauthenticated login endpoint. /mcp has its own 4MB
            # cumulative cap inside the MCP SDK transport.
            return JSONResponse(
                {"error": {"code": "payload_too_large",
                           "message": "Chunked request bodies are not accepted"}},
                status_code=413,
            )
        return await call_next(request)


class AuthMiddleware(BaseHTTPMiddleware):
    """Gate /mcp* (MCP bearer) and /admin* (admin session cookie or bearer).

    Admin sessions are read from request.app.state.admin_sessions so the
    middleware instance never needs post-construction mutation.
    """

    def __init__(self, app, settings: Settings, mcp_limiter: RateLimiter,
                 admin_limiter: RateLimiter):
        super().__init__(app)
        self.settings = settings
        self.mcp_limiter = mcp_limiter
        self.admin_limiter = admin_limiter

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path == "/mcp":
            # FastMCP sub-app is mounted at /mcp with its route at "/".
            # An exact POST /mcp would otherwise 307-redirect to /mcp/,
            # which many MCP clients do not follow. Rewrite internally.
            request.scope["path"] = "/mcp/"
            path = "/mcp/"
        if path.startswith("/mcp"):
            return await self._guard_mcp(request, call_next)
        if path.startswith("/admin"):
            return await self._guard_admin(request, call_next, path)
        if path in META_ENDPOINTS:
            # /tools, /diagnostics and /metrics carry their own auth checks,
            # but the rate budget must not depend on that: cap anonymous and
            # authenticated hammering alike (shared budget per caller).
            allowed, retry_after = await self.mcp_limiter.allow(f"meta:{_client_key(request)}")
            if not allowed:
                log.warning("rate limited meta endpoint caller=%s path=%s rid=%s",
                            _client_key(request), path,
                            getattr(request.state, "request_id", "-"))
                return JSONResponse(
                    {"error": {"code": "rate_limited",
                               "message": "Rate limit exceeded, retry later"}},
                    status_code=429,
                    headers={"Retry-After": str(int(retry_after) + 1)},
                )
        return await call_next(request)

    async def _guard_mcp(self, request: Request, call_next):
        settings = self.settings
        request_id = getattr(request.state, "request_id", "-")
        if not settings.MCP_ACCESS_TOKEN:
            log.warning("rejected mcp request: no token configured rid=%s", request_id)
            return JSONResponse(
                {"error": {"code": "service_misconfigured",
                           "message": "Service auth is not configured"}},
                status_code=503,
            )
        import hmac as _hmac

        token = extract_bearer(request)
        if not token or not _hmac.compare_digest(token.encode(), settings.MCP_ACCESS_TOKEN.encode()):
            log.info("rejected mcp request: bad credentials from %s rid=%s",
                     _client_key(request), request_id)
            return JSONResponse(
                {"error": {"code": "unauthorized",
                           "message": "Invalid or missing MCP access token"}},
                status_code=401,
                headers={
                    # Self-describing: point spec-compliant clients at the
                    # protected-resource metadata, which declares header
                    # bearer support and an EMPTY authorization_servers list
                    # so OAuth discovery / DCR stops immediately.
                    "WWW-Authenticate": (
                        'Bearer error="invalid_token", '
                        f'resource_metadata="{resource_metadata_url(request, settings)}"'
                    ),
                },
            )
        # Tool policy is a security boundary. Never let an authenticated
        # client reach the unwrapped Spectre app when the policy DB failed.
        gateway_state = getattr(request.app.state, "state", None)
        if gateway_state is None or not gateway_state.policy_ready:
            return JSONResponse(
                {"error": {"code": "policy_unavailable",
                           "message": "MCP policy is temporarily unavailable"}},
                status_code=503,
            )
        allowed, retry_after = await self.mcp_limiter.allow(f"mcp:{_client_key(request)}")
        if not allowed:
            log.warning("rate limited mcp caller=%s fp=%s rid=%s", _client_key(request),
                        token_fingerprint(token), request_id)
            return JSONResponse(
                {"error": {"code": "rate_limited",
                           "message": "Rate limit exceeded, retry later"}},
                status_code=429,
                headers={"Retry-After": str(int(retry_after) + 1)},
            )
        fp_token = caller_fp_var.set(token_fingerprint(token))
        try:
            return await call_next(request)
        finally:
            caller_fp_var.reset(fp_token)

    async def _guard_admin(self, request: Request, call_next, path: str):
        settings = self.settings
        request_id = getattr(request.state, "request_id", "-")
        # Static console assets are exempt from the admin budget entirely:
        # they are public by design, fetched on every page load, and must
        # never be answerable with the 429 body (a JSON stylesheet/script
        # blanks the console). Everything else keeps the budget below.
        if _is_admin_asset(path):
            return await call_next(request)
        # Rate limit every other /admin hit (incl. public paths: login brute-force).
        allowed, retry_after = await self.admin_limiter.allow(f"admin:{_client_key(request)}")
        if not allowed:
            log.warning("rate limited admin caller=%s rid=%s", _client_key(request), request_id)
            return JSONResponse(
                {"error": {"code": "rate_limited",
                           "message": "Rate limit exceeded, retry later"}},
                status_code=429,
                headers={"Retry-After": str(int(retry_after) + 1)},
            )
        if _path_matches_public(path):
            return await call_next(request)
        if not settings.ADMIN_TOKEN:
            log.warning("rejected admin request: no token configured rid=%s", request_id)
            return JSONResponse(
                {"error": {"code": "service_misconfigured",
                           "message": "Admin auth is not configured"}},
                status_code=503,
            )
        # Session cookie (browser) OR bearer token (scripts).
        authorized = False
        admin_sessions = getattr(request.app.state, "admin_sessions", None)
        if admin_sessions is not None:
            sid = request.cookies.get("kxstrel_admin_session")
            if await admin_sessions.validate(sid):
                authorized = True
        if not authorized:
            import hmac as _hmac

            token = extract_bearer(request)
            if token and _hmac.compare_digest(token.encode(), settings.ADMIN_TOKEN.encode()):
                authorized = True
        if not authorized:
            log.info("rejected admin request from %s rid=%s", _client_key(request), request_id)
            return JSONResponse(
                {"error": {"code": "unauthorized",
                           "message": "Invalid or missing admin access token"}},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
        return await call_next(request)


# Re-export for routes that prefer dependency-style checks.
__all__ = ["RequestIdMiddleware", "RequestSizeLimitMiddleware", "AuthMiddleware",
           "client_key"]
