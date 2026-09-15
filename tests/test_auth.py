"""Public endpoint auth contract: /health and /status are open and
non-sensitive, the MCP and diagnostics surfaces are not."""

import os


def test_health_open_and_minimal(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "Kxstrel X MCP"
    blob = r.text.lower()
    assert "auth_token" not in blob and "ct0" not in blob


def test_status_open_non_sensitive(client):
    r = client.get("/status")
    assert r.status_code == 200
    body = r.json()
    assert body["x_status"] in {"CONNECTED", "INVALID_SESSION", "RATE_LIMITED",
                                "X_UNAVAILABLE", "CONFIG_ERROR", "NOT_CONFIGURED"}
    for forbidden in ("enc_auth_token", "enc_ct0", "auth_token", "ct0", "cookie",
                      "MCP_ACCESS_TOKEN", "ADMIN_TOKEN"):
        assert forbidden.lower() not in r.text.lower(), forbidden
    # Our own test secrets must never appear in responses either.
    assert os.environ["MCP_ACCESS_TOKEN"] not in r.text
    assert os.environ["ADMIN_TOKEN"] not in r.text


def test_mcp_rejects_wrong_token(client):
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    headers={"Authorization": "Bearer wrong-token"})
    assert r.status_code == 401


def test_tools_require_auth(client):
    assert client.get("/tools").status_code == 401
    assert client.get("/diagnostics").status_code == 401
