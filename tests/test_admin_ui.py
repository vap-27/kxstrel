"""Admin UI: session auth, CSRF guard, secret-leak resistance."""

import os
import re

ADMIN = {"Authorization": f"Bearer {os.environ['ADMIN_TOKEN']}"}
COOKIE_RE = re.compile(r"kxstrel_admin_session=[^;]+")


def _login(client):
    r = client.post("/admin/api/login", json={"token": os.environ["ADMIN_TOKEN"]})
    assert r.status_code == 200, r.text
    return r


def test_ui_shell_served_without_auth(client):
    r = client.get("/admin")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    # No secrets in the page source.
    assert os.environ["ADMIN_TOKEN"] not in r.text
    assert "auth_token" not in r.text


def test_static_assets_public_and_clean(client):
    for asset in ("/admin/assets/app.js", "/admin/assets/app.css"):
        r = client.get(asset)
        assert r.status_code == 200, asset
        assert os.environ["ADMIN_TOKEN"] not in r.text


def test_admin_api_rejects_anonymous(client):
    for path in ("/admin/api/overview", "/admin/api/accounts", "/admin/api/tools",
                 "/admin/api/usage", "/admin/api/audit"):
        assert client.get(path).status_code == 401, path


def test_login_rejects_wrong_token(client):
    r = client.post("/admin/api/login", json={"token": "wrong-token"})
    assert r.status_code == 401


def test_session_login_flow(client):
    r = _login(client)
    # Cookie: HttpOnly, SameSite=strict, path-scoped.
    set_cookie = r.headers.get("set-cookie", "")
    assert "HttpOnly" in set_cookie
    assert "samesite=strict" in set_cookie.lower() or "SameSite=strict" in set_cookie
    assert "Path=/admin" in set_cookie
    # The cookie value must NOT be the admin token.
    assert os.environ["ADMIN_TOKEN"] not in set_cookie

    # Session cookie authorizes API access.
    assert client.get("/admin/api/overview").status_code == 200
    body = client.get("/admin/api/overview").json()
    assert body["x_status"] in {"CONNECTED", "INVALID_SESSION", "RATE_LIMITED",
                                "X_UNAVAILABLE", "CONFIG_ERROR", "NOT_CONFIGURED"}

    # ... and bearer still works (scripts).
    assert client.get("/admin/api/overview", headers=ADMIN).status_code == 200


def test_logout_revokes_session(client):
    _login(client)
    r = client.post("/admin/api/logout", headers={"X-Requested-With": "XMLHttpRequest"})
    assert r.status_code == 200
    assert client.get("/admin/api/overview").status_code == 401


def test_csrf_guard_for_cookie_auth(client):
    _login(client)
    # Missing X-Requested-With on state change with cookie auth -> 403.
    r = client.post("/admin/api/accounts",
                    json={"label": "x", "auth_token": "a" * 40, "ct0": "b" * 160})
    assert r.status_code == 403
    client.cookies.clear()  # bearer path below must not ride the session
    # Bearer requests are exempt (no ambient cookie authority).
    r = client.post("/admin/account", headers=ADMIN,
                    json={"label": "csrf_probe", "auth_token": "a" * 40,
                          "ct0": "b" * 160, "enabled": False})
    assert r.status_code == 200
    client.delete("/admin/account/csrf_probe", headers=ADMIN)


def test_overview_never_leaks_secrets(client):
    _login(client)
    for path in ("/admin/api/overview", "/admin/api/accounts", "/admin/api/usage",
                 "/admin/api/audit"):
        r = client.get(path)
        assert r.status_code == 200, path
        blob = r.text.lower()
        for forbidden in ("enc_auth_token", "enc_ct0", "auth_token", "ct0",
                          "cookie", "admin_token", "mcp_access_token"):
            assert forbidden not in blob, f"{path} leaked {forbidden}"
        assert os.environ["ADMIN_TOKEN"] not in r.text
        assert os.environ["MCP_ACCESS_TOKEN"] not in r.text
    # Tool descriptions may legitimately mention the word "cookie" (spectre
    # docs text); the listing must still never carry credential values/keys.
    r = client.get("/admin/api/tools")
    assert r.status_code == 200
    assert os.environ["ADMIN_TOKEN"] not in r.text
    assert os.environ["MCP_ACCESS_TOKEN"] not in r.text
    assert "enc_auth_token" not in r.text.lower()


def test_security_headers_on_admin(client):
    r = client.get("/admin")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert "default-src 'none'" in r.headers.get("content-security-policy", "")
    # Health endpoint stays clean of admin headers (different surface).
    h = client.get("/health")
    assert h.headers.get("x-frame-options") is None


def test_metrics_requires_admin(client):
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers=ADMIN).status_code == 200
    body = client.get("/metrics", headers=ADMIN).text
    assert "kxstrel_http_requests_total" in body
