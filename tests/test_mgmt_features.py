"""Uptime persistence, client registry, session management."""

import os

ADMIN = {"Authorization": f"Bearer {os.environ['ADMIN_TOKEN']}"}
MCP = {"Authorization": f"Bearer {os.environ['MCP_ACCESS_TOKEN']}"}


def _mcp_session(client, client_name="pytest-client"):
    headers = {**MCP, "Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    r = client.post("/mcp", headers=headers, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": client_name, "version": "9.9"}}})
    sid = r.headers.get("mcp-session-id")
    client.post("/mcp", headers={**headers, "mcp-session-id": sid},
                json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    return {**headers, "mcp-session-id": sid}


def test_uptime_markers_persisted(client):
    """Overview exposes site/MCP uptime anchors that survive restarts."""
    r = client.get("/admin/api/overview", headers=ADMIN)
    assert r.status_code == 200
    body = r.json()
    assert body["service_first_started_at"]  # set on first boot, DB-persisted
    assert body["mcp_first_ok_at"]
    # /status carries the same public fields.
    s = client.get("/status").json()
    assert s["service_first_started_at"] == body["service_first_started_at"]
    assert s["mcp_first_ok_at"]


def test_uptime_meta_roundtrip(client):
    from app.db import AccountStore
    import asyncio
    import tempfile

    tmp = tempfile.mkdtemp(prefix="kxstrel-meta-")
    store = AccountStore(f"sqlite:///{tmp}/t.db")

    async def go():
        await store.connect()
        await store.init_schema()
        assert await store.get_meta("service_first_started_at") is None
        await store.set_meta("service_first_started_at", "2026-09-13T00:00:00+00:00")
        assert await store.get_meta("service_first_started_at") == "2026-09-13T00:00:00+00:00"
        await store.set_meta("service_first_started_at", "2026-09-14T00:00:00+00:00")
        await store.close()
        assert await store.get_meta("service_first_started_at") == "2026-09-14T00:00:00+00:00"

    asyncio.run(go())


def test_client_registry_records_real_handshakes(client):
    """Client names come from actual MCP initialize clientInfo."""
    _mcp_session(client, client_name="hermes")
    _mcp_session(client, client_name="openclaw")
    r = client.get("/admin/api/clients", headers=ADMIN)
    assert r.status_code == 200
    names = {c["name"] for c in r.json()["clients"]}
    assert {"hermes", "openclaw"} <= names
    by_name = {c["name"]: c for c in r.json()["clients"]}
    assert by_name["hermes"]["handshakes"] >= 1
    assert "9.9" in by_name["hermes"]["versions"]
    assert by_name["hermes"]["active"] is True
    assert by_name["hermes"]["first_seen"]
    # Overview embeds the same data.
    ov = client.get("/admin/api/overview", headers=ADMIN).json()
    assert {"hermes", "openclaw"} <= {c["name"] for c in ov["mcp_clients"]}


def test_admin_sessions_listing_and_revoke(client):
    client.post("/admin/api/login", json={"token": os.environ["ADMIN_TOKEN"]})
    r = client.get("/admin/api/sessions", headers=ADMIN)
    assert r.status_code == 200
    sessions = r.json()["sessions"]
    assert len(sessions) >= 1
    assert all("hash_prefix" in s for s in sessions)
    # Cookie values never appear (only hash prefixes).
    assert os.environ["ADMIN_TOKEN"] not in r.text

    r = client.delete("/admin/api/sessions", headers=ADMIN)
    assert r.status_code == 200 and r.json()["revoked"] >= 1
    # Session gone: overview now 401 via cookie (bearer still fine).
    assert client.get("/admin/api/overview").status_code == 401
    assert client.get("/admin/api/overview", headers=ADMIN).status_code == 200
