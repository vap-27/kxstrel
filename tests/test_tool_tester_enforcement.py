"""B8: the dashboard tool tester must not be a policy bypass.

Two claims are tested separately and honestly:

1. ``FastMCP.call_tool`` on the INSTALLED fastmcp (4.0.3) traverses the
   registered middleware chain by default — proven with a spy middleware and
   with the gateway's own UsageAndFlagsMiddleware attached to a fresh server.
   So the original dashboard path was NOT observed to bypass enforcement.
2. Enforcement does not depend on that behaviour: the tester handler also
   refuses hard-blocked tools, server-local file paths, admin-disabled tools
   and any non-read-only tool without an explicit opt-in.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware

from app.db import AccountStore
from app.models import GatewayState
from app import tool_middleware

ADMIN = {"Authorization": f"Bearer {os.environ['ADMIN_TOKEN']}"}


# ── 1. does call_tool run middleware in the installed version? ───────────

async def test_fastmcp_call_tool_runs_middleware():
    """The claim in the old docstring, verified against the installed version."""
    server = FastMCP("middleware-probe")

    @server.tool
    async def probe_echo(text: str = "x") -> str:
        return f"ran:{text}"

    seen: list[str] = []

    class Spy(Middleware):
        async def on_call_tool(self, context, call_next):
            seen.append(context.message.name)
            return await call_next(context)

    server.add_middleware(Spy())
    result = await server.call_tool("probe_echo", {"text": "hi"})
    assert seen == ["probe_echo"]
    assert "ran:hi" in str(result)
    # And the documented escape hatch really escapes (proves the spy was the
    # only thing running, not something incidental).
    seen.clear()
    await server.call_tool("probe_echo", {"text": "hi"}, run_middleware=False)
    assert seen == []


async def test_gateway_middleware_enforces_through_call_tool(tmp_path):
    """The gateway's own middleware, attached to a server, actually blocks."""
    server = FastMCP("enforcement-probe")

    @server.tool
    async def probe_read(text: str = "x") -> str:
        return f"ran:{text}"

    @server.tool
    async def probe_media(file_path: str) -> str:  # pragma: no cover - never runs
        return f"should-not-run:{file_path}"

    store = AccountStore(f"sqlite:///{tmp_path}/probe.db")
    await store.connect()
    await store.init_schema()
    await store.set_tool_flag("probe_read", False)  # admin-disabled

    state = GatewayState()
    state.tool_names = ["probe_read", "probe_media"]
    middleware = tool_middleware.attach(server, store, state)
    assert middleware is not None, "gateway middleware failed to attach"

    # (a) admin-disabled tool: refused by the flag check.
    with pytest.raises(ToolError, match="disabled by the administrator"):
        await server.call_tool("probe_read", {"text": "hi"})

    # (b) hard-blocked tool name: refused regardless of flags.
    with pytest.raises(ToolError, match="remote gateway mode"):
        await server.call_tool("upload_media", {"file_path": "/etc/passwd"})

    # (c) server-local file path on an otherwise allowed tool.
    with pytest.raises(ToolError, match="file_path"):
        await server.call_tool("probe_media", {"file_path": "/etc/passwd"})

    # (d) usage was recorded for the refusals (the chain really ran).
    rows = await store.list_tool_usage(limit=10)
    assert rows, "middleware recorded no usage rows"
    assert all(row["ok"] is False for row in rows)
    await store.close()


def test_middleware_blocks_nested_file_path():
    assert tool_middleware.contains_file_path({"file_path": "x"}) is True
    assert tool_middleware.contains_file_path({"a": {"b": [{"file_path": "x"}]}}) is True
    assert tool_middleware.contains_file_path({"File_Path": "x"}) is True
    assert tool_middleware.contains_file_path({"text": "hello", "n": 1}) is False
    assert tool_middleware.contains_file_path("file_path=/etc/passwd") is False


# ── 2. tester handler gates (independent of fastmcp behaviour) ───────────

def test_tester_refuses_hard_blocked_tool(client):
    resp = client.post("/admin/api/tools/upload_media/test", headers=ADMIN,
                       json={"arguments": {"file_path": "/etc/passwd"}})
    assert resp.status_code == 403
    assert "hard-blocked" in resp.text


def test_tester_refuses_local_file_arguments(client):
    resp = client.post("/admin/api/tools/post_tweet/test", headers=ADMIN,
                       json={"arguments": {"text": "hi", "file_path": ".env"}})
    assert resp.status_code == 403
    assert "file_path" in resp.text


def test_tester_refuses_nested_local_file_arguments(client):
    resp = client.post("/admin/api/tools/post_tweet/test", headers=ADMIN,
                       json={"arguments": {"text": "hi", "meta": {"file_path": ".env"}},
                             "allow_non_read_only": True})
    assert resp.status_code == 403


def test_tester_respects_disabled_flag(client):
    assert client.post("/admin/api/tools/get_user", headers=ADMIN,
                       json={"enabled": False}).status_code == 200
    try:
        resp = client.post("/admin/api/tools/get_user/test", headers=ADMIN,
                           json={"arguments": {"username": "nasa"}})
        assert resp.status_code == 403
        assert "disabled by the administrator" in resp.text
    finally:
        client.post("/admin/api/tools/get_user", headers=ADMIN, json={"enabled": True})


def test_tester_requires_opt_in_for_non_read_only_tools(client):
    # No opt-in: refused before any execution.
    resp = client.post("/admin/api/tools/set_auto_rotate/test", headers=ADMIN,
                       json={"arguments": {"enabled": True}})
    assert resp.status_code == 403
    body = resp.json()
    assert body["error"]["code"] == "write_tool_requires_opt_in"

    # With the explicit opt-in the same call is allowed to run (no X traffic:
    # this tool only flips a process-local switch).
    resp = client.post("/admin/api/tools/set_auto_rotate/test", headers=ADMIN,
                       json={"arguments": {"enabled": True}, "allow_non_read_only": True})
    assert resp.status_code == 200, resp.text
    assert resp.json().get("ok") is True


def test_tester_read_only_tools_run_without_opt_in(client):
    """Read-only path stays frictionless (X may be unconfigured; envelope ok)."""
    resp = client.post("/admin/api/tools/get_trends/test", headers=ADMIN,
                       json={"arguments": {"limit": 1}})
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body.get("ok"), bool)
    assert "result" in body or "error" in body


def test_tester_csrf_for_cookie_auth(client):
    """Cookie-authenticated tester calls must carry the CSRF header too."""
    client.post("/admin/api/login", json={"token": os.environ["ADMIN_TOKEN"]})
    r = client.post("/admin/api/tools/get_trends/test", json={"arguments": {}})
    assert r.status_code == 403
    client.cookies.clear()


def test_tester_rejects_anonymous_and_mcp_token(client):
    client.cookies.clear()
    assert client.post("/admin/api/tools/get_user/test",
                       json={"arguments": {}}).status_code == 401
    assert client.post("/admin/api/tools/get_user/test",
                       headers={"Authorization": f"Bearer {os.environ['MCP_ACCESS_TOKEN']}"},
                       json={"arguments": {}}).status_code == 401