"""Regression tests for the security-audit fixes (2026-09-13 audit round)."""

import os

import httpx
import pytest
from fastapi.testclient import TestClient

from app.logging_setup import redact, sanitize_error

ADMIN = {"Authorization": f"Bearer {os.environ['ADMIN_TOKEN']}"}
MCP = {"Authorization": f"Bearer {os.environ['MCP_ACCESS_TOKEN']}"}


def _login(client):
    return client.post("/admin/api/login", json={"token": os.environ["ADMIN_TOKEN"]})


def _mcp_session(client):
    headers = {**MCP, "Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    r = client.post("/mcp", headers=headers, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "t", "version": "1"}}})
    sid = r.headers.get("mcp-session-id")
    client.post("/mcp", headers={**headers, "mcp-session-id": sid},
                json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    return {**headers, "mcp-session-id": sid}


def test_hard_blocked_tools_rejected(client):
    """C-1: media tools with local file access must be hard-blocked."""
    headers = _mcp_session(client)
    r = client.post("/mcp", headers=headers, json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "upload_media", "arguments": {"file_path": "/etc/passwd"}}})
    assert r.status_code == 200
    assert "remote gateway mode" in r.text
    assert "passwd" not in r.text  # the path itself must not be echoed


def test_file_path_argument_blocked_even_on_other_tools(client):
    """C-1: any tool call carrying a file_path argument is rejected."""
    headers = _mcp_session(client)
    r = client.post("/mcp", headers=headers, json={
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "post_tweet",
                   "arguments": {"text": "hi", "file_path": ".env"}}})
    assert r.status_code == 200
    assert "file_path" in r.text and "disabled in remote" in r.text


def test_remove_account_hard_blocked(client):
    """M-2: pool mutation via MCP is blocked; use the admin API instead."""
    headers = _mcp_session(client)
    r = client.post("/mcp", headers=headers, json={
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "remove_account", "arguments": {"username": "myaccount"}}})
    assert "blocked" in r.text.lower()


def test_xff_rightmost_used_for_rate_limit(client):
    """H-2: spoofed leftmost XFF must not mint fresh rate-limit buckets."""
    from app.middleware import _client_key
    from starlette.requests import Request

    scope = {"type": "http", "path": "/", "headers": [
        (b"x-forwarded-for", b"1.2.3.4, 5.6.7.8")], "client": ("9.9.9.9", 1234)}
    req = Request(scope)
    assert _client_key(req) == "5.6.7.8"  # rightmost = trusted proxy append


def test_canonical_path_bounded_labels():
    """H-1: raw paths never become metric labels."""
    from app.middleware import _canonical_path

    # The documented bucket set (extended with the OAuth-discovery endpoints
    # added for A2: their labels are fixed constants, never raw paths).
    allowed = {"/mcp", "/health", "/status", "/tools", "/diagnostics",
               "/metrics", "/admin", "/admin/api", "/admin/assets", "other",
               "/.well-known", "/.well-known/oauth-protected-resource",
               "/.well-known/oauth-protected-resource/mcp",
               "/.well-known/oauth-authorization-server",
               "/register", "/authorize", "/token"}
    for weird in ("/anything/random/12345", "/x" * 100, "/health", "/admin/api/accounts/z",
                  "/.well-known/oauth-protected-resource/mcp/../../etc",
                  "/.well-known/evil", "/registerXYZ"):
        label = _canonical_path(weird)
        assert label in allowed

def test_chunked_body_rejected(client):
    """H-3: chunked requests without Content-Length are refused."""
    r = client.post("/admin/api/login",
                    headers={"Transfer-Encoding": "chunked", "Content-Type": "application/json"},
                    content=b'{"token":"x"}')
    assert r.status_code == 413


def test_legacy_setup_requires_csrf_header_with_cookie(client):
    """M-2(audit1): legacy POST /admin/account now enforces anti_csrf."""
    _login(client)
    r = client.post("/admin/account", json={
        "label": "legacyprobe", "auth_token": "a" * 40, "ct0": "b" * 160})
    assert r.status_code == 403
    client.cookies.clear()
    r = client.post("/admin/account", headers=ADMIN, json={
        "label": "legacyprobe", "auth_token": "a" * 40,
        "ct0": "b" * 160, "enabled": False})
    assert r.status_code == 200
    client.delete("/admin/account/legacyprobe", headers=ADMIN)


def test_logout_requires_csrf_header_with_cookie(client):
    """L-1(audit1): logout enforces anti_csrf for cookie auth."""
    _login(client)
    r = client.post("/admin/api/logout")
    assert r.status_code == 403
    r = client.post("/admin/api/logout", headers={"X-Requested-With": "XMLHttpRequest"})
    assert r.status_code == 200


def test_redaction_json_quoted_values():
    """M-1(audit2): JSON-quoted secret values are scrubbed."""
    from app.logging_setup import redact

    out = redact('{"auth_token": "abcdef1234567890abcdef1234567890"}')
    assert "abcdef1234567890" not in out
    out = redact("auth_token='abcdef1234567890abcdef123'")
    assert "abcdef1234567890" not in out
    out = redact('{"ct0": "short"}')
    assert "short" not in out


def test_request_id_validation(client):
    """L-2(audit3): hostile X-Request-ID is replaced, not echoed."""
    r = client.get("/health", headers={"X-Request-ID": "<script>alert(1)//" + "x" * 200})
    echoed = r.headers.get("x-request-id", "")
    assert "<script>" not in echoed and len(echoed) <= 64


def test_security_headers_minimal_everywhere(client):
    """L-4(audit3): non-admin surfaces get nosniff too."""
    r = client.get("/health")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("content-security-policy") is None  # CSP stays admin-only


def test_tool_name_truncated_in_usage_log(client):
    """L-5(audit3): oversized tool names don't break usage logging."""
    from app.db import AccountStore
    import tempfile

    tmp = tempfile.mkdtemp(prefix="kxstrel-trunc-")
    store = AccountStore(f"sqlite:///{tmp}/t.db")

    async def go():
        await store.connect()
        await store.init_schema()
        await store.log_tool_usage("x" * 500, False, "err", 1, None)
        rows = await store.list_tool_usage(limit=5)
        await store.close()
        return rows

    import asyncio

    rows = asyncio.run(go())
    assert rows and len(rows[0]["tool_name"]) <= 128


def test_update_field_allowlist():
    """L-1(audit2): non-allowlisted (table, field) pairs are rejected."""
    from app.db import AccountStore
    import asyncio
    import tempfile

    store = AccountStore(f"sqlite:///{tempfile.mkdtemp(prefix='kxstrel-allowlist-')}/t.db")
    with pytest.raises(ValueError):
        asyncio.run(store.update_field("x_accounts", "x", "enc_auth_token", "y"))


def test_backup_audit_no_duplicates():
    """M-5(audit2): repeated backups don't duplicate audit rows.

    Snapshots replaced the in-place mirror: each run writes its own partition,
    so an audit row appears exactly once per snapshot by construction (the old
    design needed a high-watermark check to avoid re-inserting it), and the
    legacy mirror table in the backup store is no longer written at all."""
    import asyncio
    import tempfile

    from app.backup import BackupManager
    from app.db import AccountStore
    from app.models import GatewayState

    async def go():
        tmp = tempfile.mkdtemp(prefix="kxstrel-bk-")
        primary = AccountStore(f"sqlite:///{tmp}/p.db")
        backup = AccountStore(f"sqlite:///{tmp}/b.db")
        for s in (primary, backup):
            await s.connect()
            await s.init_schema()
        await primary.log_admin_action("login_ok", "d1", "r1")
        mgr = BackupManager(backup, GatewayState())
        mgr.bind_primary(primary)
        first = await mgr.run("t")
        second = await mgr.run("t")
        per_snapshot = {
            row["snapshot_at"]: row["n"] for row in await backup._fetch_all(
                "SELECT snapshot_at, COUNT(*) AS n FROM backup_admin_audit"
                " GROUP BY snapshot_at")
        }
        mirror = await backup.dump_admin_audit()
        await primary.close()
        await backup.close()
        return first, second, per_snapshot, mirror

    first, second, per_snapshot, mirror = asyncio.run(go())
    assert first["ok"] and second["ok"]
    assert first["snapshot_at"] != second["snapshot_at"]
    assert list(per_snapshot.values()) == [1, 1]  # one copy per snapshot, no duplicates
    assert mirror == []  # the legacy mirror table is unused now


def test_metrics_export_contains_tool_and_admin_counters(client):
    r = client.get("/metrics", headers=ADMIN)
    assert r.status_code == 200
    assert "kxstrel_tool_calls_total" in r.text
    assert "kxstrel_admin_actions_total" in r.text
    # Path labels are canonical only (fixed bucket set; the OAuth-discovery
    # buckets added for A2 are fixed constants too).
    import re

    allowed = {"/mcp", "/health", "/status", "/tools", "/diagnostics",
               "/metrics", "/admin", "/admin/api", "/admin/assets", "other",
               "/.well-known", "/.well-known/oauth-protected-resource",
               "/.well-known/oauth-protected-resource/mcp",
               "/.well-known/oauth-authorization-server",
               "/register", "/authorize", "/token"}
    for m in re.finditer(r'kxstrel_http_requests_total\{path="([^"]+)"', r.text):
        assert m.group(1) in allowed


# ── log/error redaction primitives ───────────────────────────────────────
# Merged from test_redaction.py: these are the primitives every redaction
# assertion above (and every response/log path) relies on.

def test_bearer_redacted():
    out = redact("Authorization: Bearer supersecretvaluethatikeep")
    assert "supersecretvaluethatikeep" not in out
    assert "Bearer" in out


def test_cookie_assignment_redacted():
    out = redact('cookies "auth_token=abcdef0123456789abcdef0123456789abcdef01; ct0=xyz"')
    assert "abcdef0123456789" not in out


def test_long_blob_redacted():
    blob = "x" * 160  # ct0-shaped
    assert blob not in redact(f"value={blob}")


def test_url_password_redacted():
    out = redact("postgresql://user:s3cr3tpass@host:5432/db")
    assert "s3cr3tpass" not in out
    assert "host" in out


def test_sanitize_truncates_and_cleans():
    long_err = "boom " + "y" * 500
    out = sanitize_error(long_err)
    assert len(out) <= 300
    assert "y" * 40 not in out
