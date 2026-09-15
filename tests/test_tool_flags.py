"""Tool flags + usage logging middleware (sqlite store, no X traffic)."""

import os

from fastmcp.exceptions import ToolError

MCP = {"Authorization": f"Bearer {os.environ['MCP_ACCESS_TOKEN']}"}
ADMIN = {"Authorization": f"Bearer {os.environ['ADMIN_TOKEN']}"}


def test_tool_flag_default_enabled(client):
    r = client.get("/admin/api/tools", headers=ADMIN)
    assert r.status_code == 200
    body = r.json()
    assert body["count"] > 50
    assert all(t["enabled"] is True for t in body["tools"])


def test_disable_tool_blocks_calls(client):
    # Disable 'get_trends' (harmless read tool we can invoke without X).
    r = client.post("/admin/api/tools/get_trends", headers=ADMIN,
                    json={"enabled": False})
    assert r.status_code == 200 and r.json()["enabled"] is False

    # Listing reflects the flag.
    tools = {t["name"]: t for t in
             client.get("/admin/api/tools", headers=ADMIN).json()["tools"]}
    assert tools["get_trends"]["enabled"] is False

    # The MCP layer rejects calls to the disabled tool with a clean error.
    init = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "t", "version": "1"}},
    }
    headers = {**MCP, "Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    r = client.post("/mcp", headers=headers, json=init)
    sid = r.headers.get("mcp-session-id")
    client.post("/mcp", headers={**headers, "mcp-session-id": sid},
                json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    r = client.post("/mcp", headers={**headers, "mcp-session-id": sid},
                    json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                          "params": {"name": "get_trends",
                                     "arguments": {"limit": 1}}})
    assert r.status_code == 200
    assert "disabled by the administrator" in r.text

    # Re-enable.
    client.post("/admin/api/tools/get_trends", headers=ADMIN,
                json={"enabled": True})


def test_usage_logged_after_call(client):
    # The blocked call above was recorded; assert usage rows exist and are
    # redacted (no bearer token material).
    r = client.get("/admin/api/usage?limit=10", headers=ADMIN)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= 1
    row = body["rows"][0]
    assert row["tool_name"] == "get_trends"
    assert row["ok"] is False
    assert "disabled" in (row["error"] or "")
    assert os.environ["MCP_ACCESS_TOKEN"] not in r.text
    # Caller fingerprint is a short hash, never the token itself.
    assert row["caller_fp"] is None or len(row["caller_fp"]) <= 16
