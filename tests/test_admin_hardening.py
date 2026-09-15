"""Regression tests for the admin-surface audit findings.

B5  every protected /admin route declares an explicit admin dependency
    (not just the single AuthMiddleware prefix check) and rejects anonymous
    callers.
B6  the public-path matcher is exact for /admin/api/login and
    /admin/api/session (no prefix bleed).
B7  anti_csrf warns when the session store is missing and compares the
    X-Requested-With header case-insensitively.
B9  /tools, /diagnostics and /metrics share the MCP rate budget.
B10 rotating ADMIN_TOKEN invalidates live dashboard sessions.
B11 audit records carry caller key + auth method, never the token.
B14 console static assets (/admin/assets/*) carry no rate budget at all:
    sharing the login-protection budget let a few reloads answer app.css /
    app.js with the 429 JSON body, which the browser painted as the
    stylesheet/script — a blank, unstyled console.
"""

from __future__ import annotations

import asyncio
import logging
import os
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.rate_limit import RateLimiter

ADMIN = {"Authorization": f"Bearer {os.environ['ADMIN_TOKEN']}"}

# (method, path, json body) for every route that must never answer a request
# without admin credentials.
PROTECTED_ROUTES: list[tuple[str, str, dict | None]] = [
    ("GET", "/admin/api/overview", None),
    ("GET", "/admin/api/tools", None),
    ("GET", "/admin/api/usage", None),
    ("GET", "/admin/api/audit", None),
    ("GET", "/admin/api/clients", None),
    ("GET", "/admin/api/sessions", None),
    ("GET", "/admin/api/accounts", None),
    ("GET", "/admin/accounts", None),
    ("POST", "/admin/api/accounts", {"label": "x", "auth_token": "a" * 40, "ct0": "b" * 160}),
    ("POST", "/admin/account", {"label": "x", "auth_token": "a" * 40, "ct0": "b" * 160}),
    ("POST", "/admin/api/validate", None),
    ("POST", "/admin/validate", None),
    ("POST", "/admin/api/backup", None),
    ("POST", "/admin/api/backup/restore", None),
    ("POST", "/admin/api/tools/get_trends", {"enabled": True}),
    ("POST", "/admin/api/tools/get_trends/test", {"arguments": {"limit": 1}}),
    ("PATCH", "/admin/api/accounts/probe", {"enabled": False}),
    ("DELETE", "/admin/api/accounts/probe", None),
    ("DELETE", "/admin/account/probe", None),
    ("DELETE", "/admin/api/sessions", None),
    ("GET", "/admin/api/upstream-capture", None),
    ("POST", "/admin/api/upstream-capture", {"operations": []}),
    ("DELETE", "/admin/api/upstream-capture", None),
]

PUBLIC_ROUTES = [
    ("GET", "/admin"),
    ("GET", "/admin/"),
    ("GET", "/admin/assets/app.js"),
    ("GET", "/admin/api/session"),
]


# ── B5 ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("method,path,body", PROTECTED_ROUTES)
def test_protected_admin_routes_reject_anonymous(client, method, path, body):
    client.cookies.clear()
    resp = client.request(method, path, json=body)
    assert resp.status_code in (401, 403), f"{method} {path} -> {resp.status_code} {resp.text[:200]}"


def test_every_protected_admin_route_declares_the_admin_dependency():
    """Structural guard: a new protected route must attach the gate itself."""
    import re

    from app.routes_admin import router as admin_router

    declared: list[tuple[re.Pattern, set[str]]] = []
    for route in admin_router.routes:
        names = {getattr(d.dependency, "__name__", "") for d in getattr(route, "dependencies", [])}
        pattern = re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", route.path) + "$")
        declared.append((pattern, names))

    def dependencies_for(path: str) -> set[str]:
        return {name for pattern, names in declared if pattern.match(path) for name in names}

    for _method, path, _body in PROTECTED_ROUTES:
        assert "require_admin_access" in dependencies_for(path), \
            f"{path} does not declare require_admin_access"

    for _method, path in PUBLIC_ROUTES:
        assert "require_admin_access" not in dependencies_for(path), \
            f"{path} is public and must not require admin credentials"


def test_admin_dependency_rejects_mcp_token(client):
    """The admin gate never accepts the MCP token."""
    client.cookies.clear()
    resp = client.get("/admin/api/overview",
                      headers={"Authorization": f"Bearer {os.environ['MCP_ACCESS_TOKEN']}"})
    assert resp.status_code == 401


# ── B6 ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "/admin/api/loginSteal",
    "/admin/api/sessionSteal",
    "/admin/api/login/extra",
    "/admin/api/session/extra",
])
def test_public_admin_routes_match_exactly(client, path):
    client.cookies.clear()
    assert client.get(path).status_code == 401


def test_actually_public_admin_paths_stay_public(client):
    client.cookies.clear()
    assert client.get("/admin/api/session").status_code == 200
    assert client.get("/admin/assets/app.js").status_code == 200
    assert client.get("/admin").status_code == 200


# ── B7 ───────────────────────────────────────────────────────────────────

def test_csrf_header_compared_case_insensitively(client):
    client.cookies.clear()
    client.post("/admin/api/login", json={"token": os.environ["ADMIN_TOKEN"]})
    resp = client.post("/admin/api/logout", headers={"X-Requested-With": "xmlhttprequest"})
    assert resp.status_code == 200
    client.cookies.clear()


def test_anti_csrf_warns_and_fails_open_without_session_store(caplog):
    from app.routes_admin import anti_csrf

    scope = {
        "type": "http",
        "app": SimpleNamespace(state=SimpleNamespace(admin_sessions=None)),
        "headers": [],
        "method": "POST",
        "path": "/admin/api/logout",
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("1.2.3.4", 1234),
    }
    request = Request(scope)
    with caplog.at_level(logging.WARNING, logger="kxstrel-x-mcp.admin"):
        asyncio.run(anti_csrf(request))  # must not raise
    assert any("anti_csrf" in rec.message for rec in caplog.records), \
        "missing session store must be logged, not silent"


# ── B10 ──────────────────────────────────────────────────────────────────

def test_session_rotation_unit():
    from app.admin_sessions import AdminSessionStore

    async def go():
        store = AdminSessionStore("A" * 48, 8)
        sid, _ = await store.create()
        assert await store.validate(sid) is True
        store.admin_token = "B" * 48  # rotation
        assert await store.validate(sid) is False
        # New sessions bind to the new token.
        sid2, _ = await store.create()
        assert await store.validate(sid2) is True
        # No session id => no validation, and old ids stay dead.
        assert await store.validate(sid) is False
        assert await store.validate(None) is False

    asyncio.run(go())


def test_admin_token_rotation_invalidates_live_dashboard_session(client):
    client.cookies.clear()
    login = client.post("/admin/api/login", json={"token": os.environ["ADMIN_TOKEN"]})
    assert login.status_code == 200
    assert client.get("/admin/api/overview").status_code == 200

    sessions = client.app.state.admin_sessions
    original = sessions.admin_token
    try:
        sessions.admin_token = "rotated-" + "z" * 40
        # Existing cookie no longer authorizes anything.
        assert client.get("/admin/api/overview").status_code == 401
        # ... and the old token cannot mint a new session.
        assert client.post("/admin/api/login",
                           json={"token": original}).status_code == 401
    finally:
        sessions.admin_token = original
    client.cookies.clear()


# ── B11 ──────────────────────────────────────────────────────────────────

def test_audit_records_caller_and_auth_method_bearer(client):
    client.cookies.clear()
    resp = client.post("/admin/api/tools/get_trends", headers=ADMIN, json={"enabled": True})
    assert resp.status_code == 200
    rows = client.get("/admin/api/audit", headers=ADMIN).json()["rows"]
    row = next(r for r in rows if r["action"] == "tool_toggle")
    assert "caller=" in row["detail"]
    assert "via=bearer" in row["detail"]
    assert os.environ["ADMIN_TOKEN"] not in row["detail"]


def test_audit_records_session_auth_method_for_cookie_callers(client):
    client.cookies.clear()
    client.post("/admin/api/login", json={"token": os.environ["ADMIN_TOKEN"]})
    resp = client.post("/admin/api/tools/get_trends",
                       headers={"X-Requested-With": "XMLHttpRequest"},
                       json={"enabled": True})
    assert resp.status_code == 200
    rows = client.get("/admin/api/audit", headers=ADMIN).json()["rows"]
    row = next(r for r in rows if r["action"] == "tool_toggle")
    assert "via=session" in row["detail"]
    client.cookies.clear()


# ── B9 ───────────────────────────────────────────────────────────────────

def _app_with_limits(tmp_path, **overrides):
    from cryptography.fernet import Fernet

    from app.config import Settings
    from app.main import create_app

    settings = Settings(
        MCP_ACCESS_TOKEN="m" * 48,
        ADMIN_TOKEN="a" * 48,
        CREDENTIAL_ENCRYPTION_KEY=Fernet.generate_key().decode(),
        DATABASE_URL=f"sqlite:///{tmp_path}/rate.db",
        SPECTRE_DB_PATH=f"{tmp_path}/spectre.db",
        VALIDATE_ON_STARTUP=False,
        SESSION_CHECK_INTERVAL_SECONDS=3600,
        LOG_LEVEL="WARNING",
        **overrides,
    )
    return create_app(settings)


def test_metadata_endpoints_share_the_rate_budget(tmp_path):
    app = _app_with_limits(tmp_path, RATE_LIMIT_MCP_PER_MIN=2)
    mcp = {"Authorization": f"Bearer {'m' * 48}"}
    admin = {"Authorization": f"Bearer {'a' * 48}"}
    with TestClient(app) as client:
        assert client.get("/tools", headers=mcp).status_code == 200
        assert client.get("/diagnostics", headers=mcp).status_code == 200
        blocked = client.get("/metrics", headers=admin)
        assert blocked.status_code == 429
        assert blocked.headers.get("retry-after")
        assert blocked.json()["error"]["code"] == "rate_limited"


def test_metadata_endpoints_not_rate_limited_below_budget(tmp_path):
    app = _app_with_limits(tmp_path, RATE_LIMIT_MCP_PER_MIN=60)
    admin = {"Authorization": f"Bearer {'a' * 48}"}
    with TestClient(app) as client:
        assert client.get("/metrics", headers=admin).status_code == 200
        assert client.get("/metrics").status_code == 401  # auth still enforced


# ── B14 ──────────────────────────────────────────────────────────────────

# Deliberately tiny admin budget: 429s are deterministic without sleeping,
# and an asset burst of a few dozen requests is "well above" it.
ASSET_BUDGET = 3


def _app_with_asset_budget(tmp_path):
    return _app_with_limits(tmp_path, RATE_LIMIT_ADMIN_PER_MIN=ASSET_BUDGET)


def _exhaust_admin_budget(client):
    """Spend the whole budget on a non-asset path until a 429 proves it is
    gone (tolerant of requests a test made before calling this)."""
    statuses = [client.get("/admin").status_code for _ in range(ASSET_BUDGET + 2)]
    assert 429 in statuses, f"budget never ran out: {statuses}"


def test_asset_burst_above_the_admin_budget_never_429s(tmp_path):
    """A page load costs one app.css + one app.js; 40 hard refreshes must be
    served even though the shared budget covers only three requests."""
    app = _app_with_asset_budget(tmp_path)
    with TestClient(app) as client:
        css = {client.get("/admin/assets/app.css").status_code for _ in range(40)}
        js = {client.get("/admin/assets/app.js").status_code for _ in range(40)}
        assert css == {200}, css
        assert js == {200}, js


def test_assets_are_served_as_real_css_and_js_not_the_429_body(tmp_path):
    """The blank-console mode was the JSON error body under a .css/.js URL."""
    app = _app_with_asset_budget(tmp_path)
    with TestClient(app) as client:
        css = client.get("/admin/assets/app.css")
        js = client.get("/admin/assets/app.js")
        assert css.status_code == 200
        assert css.headers["content-type"].startswith("text/css")
        assert "rate_limited" not in css.text[:200]
        assert js.status_code == 200
        assert js.headers["content-type"].startswith(
            ("text/javascript", "application/javascript"))
        assert "rate_limited" not in js.text[:200]


def test_assets_survive_a_fully_exhausted_budget(tmp_path):
    """After the budget is gone a reload must still render the console."""
    app = _app_with_asset_budget(tmp_path)
    with TestClient(app) as client:
        _exhaust_admin_budget(client)
        for _ in range(5):
            assert client.get("/admin/assets/app.css").status_code == 200
            assert client.get("/admin/assets/app.js").status_code == 200


def test_admin_api_login_and_public_paths_still_429(tmp_path):
    """The exemption is exactly the asset family: login brute-force
    protection keeps the budget (and its response contract)."""
    app = _app_with_asset_budget(tmp_path)
    with TestClient(app) as client:
        _exhaust_admin_budget(client)
        for method, path, body in (
            ("GET", "/admin", None),
            ("GET", "/admin/api/session", None),
            ("GET", "/admin/api/overview", None),
            ("POST", "/admin/api/login", {"token": "guessed-token"}),
        ):
            resp = client.request(method, path, json=body)
            assert resp.status_code == 429, f"{method} {path} -> {resp.status_code}"
            assert resp.json()["error"]["code"] == "rate_limited"
            assert resp.headers.get("retry-after")


def test_exhausted_budget_blocks_even_a_valid_admin_bearer(tmp_path):
    """The budget sits in front of auth: a correct token does not refill it."""
    app = _app_with_asset_budget(tmp_path)
    bearer = {"Authorization": f"Bearer {'a' * 48}"}  # the app's own ADMIN_TOKEN
    with TestClient(app) as client:
        assert client.get("/admin/api/overview", headers=bearer).status_code == 200
        _exhaust_admin_budget(client)
        resp = client.get("/admin/api/overview", headers=bearer)
        assert resp.status_code == 429
        assert resp.json()["error"]["code"] == "rate_limited"


def test_asset_exemption_is_exactly_the_public_asset_family():
    """The exemption derives from the public prefixes (assets are public by
    design); pin the classification so a future public prefix is a conscious
    rate-limit decision rather than a silent inheritance."""
    from app.middleware import (ADMIN_ASSET_PREFIXES, ADMIN_PUBLIC_PREFIXES,
                                _is_admin_asset, _path_matches_public)

    assert ADMIN_ASSET_PREFIXES == ADMIN_PUBLIC_PREFIXES == ("/admin/assets/",)

    for path in ("/admin/assets/app.css", "/admin/assets/app.js",
                 "/admin/assets/icons/logo.svg", "/admin/assets/"):
        assert _path_matches_public(path) is True, path
        assert _is_admin_asset(path) is True, path

    # Public (no credentials needed) but still on the login-protection budget.
    for path in ("/admin", "/admin/", "/admin/api/login", "/admin/api/session"):
        assert _path_matches_public(path) is True, path
        assert _is_admin_asset(path) is False, path

    # Protected and limited. The bare mount only 307-redirects; the console
    # references the full asset paths, so it stays on the budget.
    for path in ("/admin/assets", "/admin/api/overview", "/admin/api/loginSteal",
                 "/admin/accounts", "/administrator"):
        assert _path_matches_public(path) is False, path
        assert _is_admin_asset(path) is False, path


# ── the limiter itself (unit) ────────────────────────────────────────────
# Merged from test_ratelimit.py: the endpoints' behaviour is asserted above,
# here are the window/key/concurrency properties those tests depend on.

async def test_allows_up_to_limit():
    limiter = RateLimiter(per_minute=3)
    assert (await limiter.allow("k"))[0] is True
    assert (await limiter.allow("k"))[0] is True
    assert (await limiter.allow("k"))[0] is True
    allowed, retry = await limiter.allow("k")
    assert allowed is False and retry > 0


async def test_independent_keys():
    limiter = RateLimiter(per_minute=1)
    assert (await limiter.allow("a"))[0] is True
    assert (await limiter.allow("b"))[0] is True
    assert (await limiter.allow("a"))[0] is False


def test_concurrent_safety():
    async def hammer():
        limiter = RateLimiter(per_minute=50)
        results = await asyncio.gather(*[limiter.allow("k") for _ in range(100)])
        return sum(1 for ok, _ in results if ok)

    assert asyncio.run(hammer()) == 50
