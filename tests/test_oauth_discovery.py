"""A2: the gateway declares its header-token model and declines OAuth.

A client such as mcp-remote must be able to see, without credentials, that
there is no OAuth authorization server here — so it fails fast instead of
walking discovery into Dynamic Client Registration and dying on an opaque
404. These endpoints must be public, cheap and explicit.
"""

from __future__ import annotations

import os

from fastapi.testclient import TestClient

MCP = {"Authorization": f"Bearer {os.environ['MCP_ACCESS_TOKEN']}"}
NON_OAUTH_ERROR = "unsupported_authorization_server"


def test_protected_resource_metadata_is_public_and_declines_oauth(client):
    resp = client.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Spec-compliant clients stop at an EMPTY authorization_servers list.
    assert body["authorization_servers"] == []
    # Header bearer is the declared mechanism: no OAuth flow, no browser.
    assert body["bearer_methods_supported"] == ["header"]
    assert body["resource"]
    assert body["authentication"] == "header_bearer_static_token"


def test_protected_resource_metadata_mcp_scoped_variant(client):
    resp = client.get("/.well-known/oauth-protected-resource/mcp")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["resource"].endswith("/mcp")
    assert body["authorization_servers"] == []


def test_authorization_server_metadata_is_explicitly_absent(client):
    resp = client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 404
    body = resp.json()
    assert body["error"] == NON_OAUTH_ERROR
    assert "does not implement OAuth" in body["error_description"]
    # Never FastAPI's bare default 404 body.
    assert body != {"detail": "Not Found"}
    assert "detail" not in body


def _declines_oauth(body: dict) -> bool:
    """The declination must not look like a usable OAuth surface."""
    return (body.get("registration_endpoint") is None
            and body.get("authorization_servers") == []
            and body.get("authentication") == "header_bearer_static_token")


def test_registration_authorize_token_decline_explicitly(client):
    for method, path in (("POST", "/register"), ("GET", "/register"),
                         ("GET", "/authorize"), ("POST", "/authorize"),
                         ("POST", "/token"), ("GET", "/token")):
        resp = client.request(method, path)
        assert resp.status_code == 404, f"{method} {path} -> {resp.status_code}"
        body = resp.json()
        assert body["error"] == NON_OAUTH_ERROR, f"{method} {path} body {body}"
        assert _declines_oauth(body), f"{method} {path} leaked oauth metadata"


def test_discovery_endpoints_are_reachable_without_auth(client):
    """No bearer token: straight to the metadata, never a 401."""
    client.cookies.clear()
    for path in ("/.well-known/oauth-protected-resource",
                 "/.well-known/oauth-protected-resource/mcp",
                 "/.well-known/oauth-authorization-server"):
        resp = client.get(path)
        assert resp.status_code in (200, 404), path  # 404 is the explicit declination
        assert resp.status_code != 401, path
        assert resp.json().get("detail") is None, path


def test_mcp_401_advertises_the_resource_metadata_url(client):
    """A client that probes /mcp first is pointed at the metadata."""
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert resp.status_code == 401
    header = resp.headers.get("www-authenticate", "")
    assert header.startswith("Bearer")
    assert "resource_metadata=" in header
    assert "/.well-known/oauth-protected-resource/mcp" in header


def test_tools_401_advertises_the_resource_metadata_url(client):
    resp = client.get("/tools")
    assert resp.status_code == 401
    assert "/.well-known/oauth-protected-resource/mcp" in resp.headers.get("www-authenticate", "")


def test_discovery_paths_use_bounded_metric_labels(client):
    from app.middleware import _PATH_LABELS, _canonical_path

    for path in ("/.well-known/oauth-protected-resource",
                 "/.well-known/oauth-protected-resource/mcp",
                 "/.well-known/oauth-authorization-server",
                 "/.well-known/anything/else",
                 "/register", "/authorize", "/token"):
        assert _canonical_path(path) in _PATH_LABELS


def _noredirect_client():
    from app.config import reset_settings_cache
    reset_settings_cache()
    from app.main import create_app  # noqa: PLC0415

    return TestClient(create_app(), follow_redirects=False)


def test_mcp_exact_path_no_redirect():
    """The public routes added for discovery must not shadow or weaken the
    MCP endpoint: POST /mcp answers 200 with a session id on the exact path.
    Verified with redirects disabled — real MCP clients do not reliably
    follow the 307 that the default TestClient would hide."""
    headers = {**MCP, "Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    with _noredirect_client() as client:
        resp = client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "discovery-check", "version": "1"}}})
        assert resp.status_code == 200, \
            f"got {resp.status_code} location={resp.headers.get('location')}"
        assert "mcp-session-id" in {k.lower() for k in resp.headers}
