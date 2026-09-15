"""Live verification of uptime cards, client registry, tester, sessions."""

import json
import os
import sys

import httpx

BASE = os.environ.get("KXSTREL_BASE", "https://x-mcp-9po9.onrender.com")
ADMIN = os.environ.get("KXSTREL_ADMIN", "")
MCP = os.environ.get("KXSTREL_MCP", "")
CLIENT_NAME = os.environ.get("KXSTREL_CLIENT_NAME", "hermes")

ok = True


def check(name, cond, detail=""):
    global ok
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    ok = ok and bool(cond)


with httpx.Client(timeout=120) as c:
    # 1. MCP handshake carrying a real clientInfo name.
    h = {"Authorization": f"Bearer {MCP}", "Accept": "application/json, text/event-stream",
         "Content-Type": "application/json"}
    r = c.post(f"{BASE}/mcp", headers=h, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": CLIENT_NAME, "version": "1.0"}}})
    sid = r.headers.get("mcp-session-id", "")
    check("mcp initialize", r.status_code == 200 and bool(sid))
    h["mcp-session-id"] = sid
    c.post(f"{BASE}/mcp", headers=h, json={"jsonrpc": "2.0", "method": "notifications/initialized"})

    # 2. Overview: persisted uptime markers + client registry.
    ov = c.get(f"{BASE}/admin/api/overview", headers={"Authorization": f"Bearer {ADMIN}"}).json()
    check("site uptime persisted", bool(ov.get("service_first_started_at")),
          str(ov.get("service_first_started_at")))
    check("mcp uptime persisted", bool(ov.get("mcp_first_ok_at")))
    clients = {x["name"] for x in ov.get("mcp_clients", [])}
    check(f"client '{CLIENT_NAME}' registered from real handshake", CLIENT_NAME in clients,
          json.dumps(sorted(clients)))
    check("client marked active", any(x["active"] for x in ov["mcp_clients"] if x["name"] == CLIENT_NAME))

    # 3. /status (public) carries uptime markers too.
    st = c.get(f"{BASE}/status").json()
    check("/status uptime markers", bool(st.get("service_first_started_at"))
          and bool(st.get("mcp_first_ok_at")))

    # 4. Tool tester with a real read-only call.
    t = c.post(f"{BASE}/admin/api/tools/search_users/test",
               headers={"Authorization": f"Bearer {ADMIN}"},
               json={"arguments": {"query": "nasa", "limit": 1}}).json()
    check("tool tester executes", t.get("ok") is True, json.dumps(t)[:150])
    check("tester returned nasa", "nasa" in (t.get("result") or "").lower())
    # Blocked tool stays blocked even for admin tester.
    b = c.post(f"{BASE}/admin/api/tools/upload_media/test",
               headers={"Authorization": f"Bearer {ADMIN}"},
               json={"arguments": {"file_path": "/etc/passwd"}})
    check("tester refuses blocked tool", b.status_code == 403)

    # 5. Usage log recorded the tester call.
    u = c.get(f"{BASE}/admin/api/usage?limit=5", headers={"Authorization": f"Bearer {ADMIN}"}).json()
    check("tester call in usage log", any(r["tool_name"] == "search_users" for r in u["rows"]))

    # 6. Sessions: login via browser flow, list, revoke-all.
    c.post(f"{BASE}/admin/api/login", json={"token": ADMIN})
    s = c.get(f"{BASE}/admin/api/sessions", headers={"Authorization": f"Bearer {ADMIN}"}).json()
    check("session listed", len(s["sessions"]) >= 1)
    check("no cookie values leaked", ADMIN not in json.dumps(s))
    rv = c.delete(f"{BASE}/admin/api/sessions",
                  headers={"Authorization": f"Bearer {ADMIN}", "X-Requested-With": "XMLHttpRequest"})
    check("revoke all", rv.status_code == 200 and rv.json()["revoked"] >= 1, rv.text[:100])
    check("cookie session dead after revoke",
          c.get(f"{BASE}/admin/api/overview").status_code == 401)
    check("bearer still works", c.get(f"{BASE}/admin/api/overview",
          headers={"Authorization": f"Bearer {ADMIN}"}).status_code == 200)

    # 7. Old uptime format check: verify fields exist & no secrets.
    blob = json.dumps(ov) + json.dumps(st)
    check("no secrets anywhere", ADMIN not in blob and MCP not in blob)

print("\nRESULT:", "ALL PASS" if ok else "FAILURES PRESENT")
sys.exit(0 if ok else 1)
