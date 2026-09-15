import os

MCP = {"Authorization": f"Bearer {os.environ['MCP_ACCESS_TOKEN']}"}


def test_tools_enumerated_dynamically(client):
    r = client.get("/tools", headers=MCP)
    assert r.status_code == 200, r.text
    body = r.json()
    # Dynamic: count equals the listed names; substantial surface proves we
    # mounted spectre rather than stubbing a handful of tools.
    assert body["count"] == len(body["tools"]) > 50
    names = {t["name"] for t in body["tools"]}
    for expected in ("search", "get_user", "get_tweet", "get_thread",
                     "post_tweet", "delete_tweet", "send_dm"):
        assert expected in names, f"missing {expected}"
    for tool in body["tools"]:
        assert isinstance(tool["read_only"], bool)
        assert isinstance(tool["destructive"], bool)


def test_read_write_split_sane(client):
    r = client.get("/tools", headers=MCP)
    by_name = {t["name"]: t for t in r.json()["tools"]}
    assert by_name["search"]["read_only"] is True
    assert by_name["get_user"]["read_only"] is True
    assert by_name["post_tweet"]["read_only"] is False
    assert by_name["post_tweet"]["destructive"] is True
    assert by_name["delete_tweet"]["destructive"] is True
    assert by_name["send_dm"]["destructive"] is True


def test_diagnostics_no_secrets(client):
    r = client.get("/diagnostics", headers=MCP)
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"application", "spectre", "x_session", "database", "mcp",
                         "backup", "usage_24h", "tool_concurrency"}
    assert os.environ["MCP_ACCESS_TOKEN"] not in r.text
    assert os.environ["ADMIN_TOKEN"] not in r.text
