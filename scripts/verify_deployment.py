"""Post-deploy verification against the live service (session + MCP + usage)."""

import json
import os
import sys

import httpx

BASE = os.environ.get("KXSTREL_BASE", "https://x-mcp-9po9.onrender.com")
ADMIN = os.environ.get("KXSTREL_ADMIN", "")
MCP = os.environ.get("KXSTREL_MCP", "")

ok = True


def check(name, cond, detail=""):
    global ok
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    ok = ok and bool(cond)


with httpx.Client(timeout=120) as c:
    # 1. admin login -> session cookie
    r = c.post(f"{BASE}/admin/api/login", json={"token": ADMIN})
    check("login 200", r.status_code == 200, str(r.status_code))
    sc = r.headers.get("set-cookie", "")
    check("cookie HttpOnly", "HttpOnly" in sc, sc[:120])
    check("cookie SameSite=strict", "samesite=strict" in sc.lower())
    check("cookie is not the admin token", ADMIN not in sc)

    # 2. session-cookie overview + security headers
    r = c.get(f"{BASE}/admin/api/overview")
    check("overview via cookie", r.status_code == 200, str(r.status_code))
    check("CSP header", "default-src 'none'" in r.headers.get("content-security-policy", ""))
    check("no-store", r.headers.get("cache-control") == "no-store")
    ov = r.json()
    check("x_status CONNECTED", ov["x_status"] == "CONNECTED", ov["x_status"])
    check("backup ok", ov["backup"]["ok"] is not False)

    # 3. UI shell is public and clean
    r = c.get(f"{BASE}/admin")
    check("ui shell 200", r.status_code == 200)
    check("ui no token in source", ADMIN not in r.text and MCP not in r.text)
    for asset in ("/admin/assets/app.js", "/admin/assets/app.css"):
        check(f"asset {asset.rsplit('/',1)[1]}", c.get(f"{BASE}{asset}").status_code == 200)

    # 4. logout clears session
    c.post(f"{BASE}/admin/api/logout",
           headers={"X-Requested-With": "XMLHttpRequest"})
    check("logout revokes", c.get(f"{BASE}/admin/api/overview").status_code == 401)

    # 5. MCP flow with real tool call
    h = {"Authorization": f"Bearer {MCP}", "Accept": "application/json, text/event-stream",
         "Content-Type": "application/json"}
    r = c.post(f"{BASE}/mcp", headers=h, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "verify", "version": "1"}}})
    check("mcp initialize", r.status_code == 200, str(r.status_code))
    sid = r.headers.get("mcp-session-id", "")
    check("session id returned", bool(sid))
    h2 = {**h, "mcp-session-id": sid}
    c.post(f"{BASE}/mcp", headers=h2, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    r = c.post(f"{BASE}/mcp", headers=h2, json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "get_user", "arguments": {"username": "nasa"}}})
    check("get_user nasa 200", r.status_code == 200, str(r.status_code))
    body = r.text
    check("nasa in result", "nasa" in body.lower())
    check("no secrets in response", ADMIN not in body and MCP not in body)

    # 6. usage log recorded the call
    r = c.get(f"{BASE}/admin/api/usage?limit=5", headers={"Authorization": f"Bearer {ADMIN}"})
    rows = r.json().get("rows", [])
    check("usage rows exist", len(rows) >= 1)
    if rows:
        row = rows[0]
        check("usage get_user ok", row["tool_name"] == "get_user" and row["ok"] is True,
              json.dumps(row)[:120])
        check("caller fp recorded", bool(row["caller_fp"]) and len(row["caller_fp"]) <= 16)

    # 7. metrics
    r = c.get(f"{BASE}/metrics", headers={"Authorization": f"Bearer {ADMIN}"})
    check("metrics 200", r.status_code == 200)
    check("tool counter present", "kxstrel_tool_calls_total" in r.text)

    # 8. tool toggle end-to-end
    r = c.post(f"{BASE}/admin/api/tools/get_trends",
               headers={"Authorization": f"Bearer {ADMIN}"},
               json={"enabled": False})
    check("disable tool", r.status_code == 200, str(r.status_code) + r.text[:120])
    r = c.post(f"{BASE}/mcp", headers=h2, json={
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "get_trends", "arguments": {"limit": 1}}})
    check("disabled tool rejected", "disabled by the administrator" in r.text, r.text[:200])
    c.post(f"{BASE}/admin/api/tools/get_trends",
           headers={"Authorization": f"Bearer {ADMIN}"},
           json={"enabled": True})

print("\nRESULT:", "ALL PASS" if ok else "FAILURES PRESENT")
sys.exit(0 if ok else 1)
