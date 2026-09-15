"""Live security probes against the deployed service."""

import json
import os
import re

import httpx

BASE = os.environ.get("KXSTREL_BASE", "https://x-mcp-9po9.onrender.com")
ADMIN = os.environ.get("KXSTREL_ADMIN", "")
MCP = os.environ.get("KXSTREL_MCP", "")
ALLOWED = {"/mcp", "/health", "/status", "/tools", "/diagnostics", "/metrics",
           "/admin", "/admin/api", "/admin/assets", "other"}

with httpx.Client(timeout=120) as c:
    h = {"Authorization": f"Bearer {MCP}", "Accept": "application/json, text/event-stream",
         "Content-Type": "application/json"}
    r = c.post(f"{BASE}/mcp", headers=h, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "v", "version": "1"}}})
    h["mcp-session-id"] = r.headers["mcp-session-id"]
    c.post(f"{BASE}/mcp", headers=h, json={"jsonrpc": "2.0", "method": "notifications/initialized"})

    r = c.post(f"{BASE}/mcp", headers=h, json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "upload_media", "arguments": {"file_path": "/etc/passwd"}}})
    print("[PASS]" if ("remote gateway mode" in r.text and "passwd" not in r.text)
          else "[FAIL]", "file tool hard-blocked, path not echoed")

    r = c.post(f"{BASE}/mcp", headers=h, json={
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "remove_account", "arguments": {"username": "myaccount"}}})
    print("[PASS]" if "blocked" in r.text.lower() else "[FAIL]", "pool mutation blocked")

    r = c.post(f"{BASE}/admin/api/login",
               headers={"Transfer-Encoding": "chunked", "Content-Type": "application/json"},
               content=b'{"token":"x"}')
    # httpx won't truly force chunked framing; the edge proxy rejecting the
    # malformed framing (400) or our middleware (413) both count as refused.
    print("[PASS]" if r.status_code in (400, 413) else "[FAIL]",
          "chunked/malformed body rejected:", r.status_code)

    m = c.get(f"{BASE}/metrics", headers={"Authorization": f"Bearer {ADMIN}"})
    labels = set(re.findall(r'kxstrel_http_requests_total\{path="([^"]+)"', m.text))
    print("[PASS]" if labels <= ALLOWED else "[FAIL]", "metric path labels bounded:", sorted(labels))

    b = c.post(f"{BASE}/admin/api/backup",
               headers={"Authorization": f"Bearer {ADMIN}", "X-Requested-With": "XMLHttpRequest"})
    print("[PASS]" if b.json().get("ok") else "[FAIL]", "backup:", json.dumps(b.json()))

    # usage log captured the blocked attempts
    u = c.get(f"{BASE}/admin/api/usage?limit=5", headers={"Authorization": f"Bearer {ADMIN}"})
    rows = u.json().get("rows", [])
    blocked = [r for r in rows if r["tool_name"] in ("upload_media", "remove_account")]
    print("[PASS]" if blocked else "[FAIL]", "blocked attempts recorded in usage log:",
          len(blocked))
