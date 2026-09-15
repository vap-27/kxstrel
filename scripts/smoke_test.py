#!/usr/bin/env python3
"""Deployment smoke test: service boots with no browser, health/status work,
MCP auth is enforced, the live tool list is enumerable, and secrets never
leak into responses.

Runs against a live gateway (local or Render). X credentials are NOT needed
for the default checks; pass --live to also perform REAL read-only tool calls
(get_user + search_users) and assert their result shape and content —
discovery-only success can no longer mask a broken call path.

Usage:
    python scripts/smoke_test.py --base-url http://localhost:8000
    MCP_ACCESS_TOKEN=... ADMIN_TOKEN=... python scripts/smoke_test.py --base-url https://x-mcp.onrender.com --live
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid

import httpx

FORBIDDEN_SUBSTRINGS_ENV = ("MCP_ACCESS_TOKEN", "ADMIN_TOKEN",
                            "CREDENTIAL_ENCRYPTION_KEY")


def check_no_secrets(payload: str, secrets: list[str]) -> list[str]:
    leaks = [f"secret from ${name} leaked into response" for name in FORBIDDEN_SUBSTRINGS_ENV
             for s in secrets if s and len(s) >= 8 and s in payload]
    return leaks


def parse_mcp_messages(text: str) -> list[dict]:
    """Decode JSON-RPC messages from SSE (`event: message` / `data:` framing)
    or from a plain JSON body."""
    stripped = text.strip()
    if not stripped:
        return []
    if stripped[0] in "{[":  # plain JSON (single object or array)
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if payload is not None:
            return payload if isinstance(payload, list) else [payload]
    messages: list[dict] = []
    data_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
            continue
        if not line.strip() and data_lines:
            try:
                messages.append(json.loads("\n".join(data_lines)))
            except json.JSONDecodeError:
                pass
            data_lines = []
    if data_lines:
        try:
            messages.append(json.loads("\n".join(data_lines)))
        except json.JSONDecodeError:
            pass
    return messages


def _message_with_id(messages: list[dict], request_id: str) -> dict | None:
    for msg in messages:
        if msg.get("id") == request_id:
            return msg
    return messages[-1] if messages else None


def tool_result_payload(message: dict | None) -> tuple[str, str | None]:
    """Extract displayable text from a tools/call result envelope.

    Returns (text, error). `error` is set when the envelope is malformed —
    never when the server legitimately reports an upstream tool error (that
    comes back as text with isError=true)."""
    if message is None:
        return "", "no JSON-RPC message in the response body"
    if "error" in message:
        return "", f"JSON-RPC error: {json.dumps(message['error'])[:300]}"
    result = message.get("result")
    if not isinstance(result, dict):
        return "", f"missing result object: {json.dumps(message)[:300]}"
    content = result.get("content")
    if not isinstance(content, list) or not content:
        return "", f"result.content must be a non-empty list: {json.dumps(result)[:300]}"
    first = content[0]
    if not isinstance(first, dict) or "text" not in first:
        return "", f"result.content[0].text missing: {json.dumps(first)[:300]}"
    return str(first.get("text") or ""), None


def _json_or_none(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def _find_list_of_dicts(obj) -> list | None:
    """First non-empty list of dicts anywhere in a JSON payload."""
    if isinstance(obj, list):
        if obj and all(isinstance(item, dict) for item in obj):
            return obj
        return None
    if isinstance(obj, dict):
        for value in obj.values():
            found = _find_list_of_dicts(value)
            if found:
                return found
    return None


def _validate_get_user(text: str) -> tuple[bool, str]:
    payload = _json_or_none(text)
    if not isinstance(payload, dict):
        return False, f"expected a user object, got: {text[:300]}"
    missing = [key for key in ("username", "id") if key not in payload]
    if missing:
        return False, f"missing {missing} in payload: {text[:300]}"
    return True, ""


def _validate_search_users(text: str) -> tuple[bool, str]:
    users = _find_list_of_dicts(_json_or_none(text))
    if not users:
        return False, f"expected a non-empty user list, got: {text[:300]}"
    return True, ""


def _live_call(client: httpx.Client, base: str, headers: dict, tool: str,
               arguments: dict, check, validate) -> None:
    """One real tools/call with envelope + content assertions.

    Fails loudly on an empty payload, a shape mismatch or an isError result:
    a call path that returns nothing usable must not look green."""
    request_id = uuid.uuid4().hex
    call = {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments}}
    try:
        resp = client.post(f"{base}/mcp", json=call, headers=headers, timeout=120)
    except Exception as exc:
        check(f"live {tool} reachable", False, str(exc)[:300])
        return
    if resp.status_code != 200:
        check(f"live {tool} HTTP 200", False, f"got {resp.status_code} {resp.text[:300]}")
        return
    message = _message_with_id(parse_mcp_messages(resp.text), request_id)
    text, envelope_error = tool_result_payload(message)
    if envelope_error:
        check(f"live {tool} result envelope", False, envelope_error)
        return
    is_error = bool((message.get("result") or {}).get("isError"))
    if is_error:
        check(f"live {tool} result envelope", False,
              f"server reported isError with: {text[:300]}")
        return
    if not text.strip():
        check(f"live {tool} result envelope", False,
              f"result.content[0].text was empty: {resp.text[:300]}")
        return
    ok, detail = validate(text)
    check(f"live {tool} envelope + content", ok, detail)
    if ok:
        print(f"      live {tool}: {len(text)} chars of real content")


def mcp_handshake(client: httpx.Client, base: str, token: str) -> str:
    """Minimal Streamable-HTTP handshake; returns the session id."""
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18",
                       "capabilities": {},
                       "clientInfo": {"name": "kxstrel-smoke", "version": "1.0"}}}
    resp = client.post(f"{base}/mcp", json=init, headers=headers, timeout=60)
    assert resp.status_code == 200, f"initialize failed: {resp.status_code} {resp.text[:300]}"
    session = resp.headers.get("mcp-session-id", "")
    assert session, "no mcp-session-id returned"
    # Open handshake per spec: initialized notification.
    notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    client.post(f"{base}/mcp", json=notif,
                headers={**headers, "mcp-session-id": session}, timeout=30)
    return session


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=os.environ.get("KXSTREL_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--live", action="store_true",
                        help="also call one read-only X tool (needs CONNECTED session)")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    token = os.environ.get("MCP_ACCESS_TOKEN", "")
    admin = os.environ.get("ADMIN_TOKEN", "")
    if not token:
        print("error: set MCP_ACCESS_TOKEN", file=sys.stderr)
        return 2
    secrets = [os.environ.get(n, "") for n in FORBIDDEN_SUBSTRINGS_ENV]
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = ""):
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))
        if not ok:
            failures.append(f"{name}: {detail}")

    with httpx.Client() as client:
        # 1-3: service starts, /health 200, no browser needed (implicit).
        try:
            r = client.get(f"{base}/health", timeout=15)
            check("health 200", r.status_code == 200, r.text[:200])
            check("health shape", r.json().get("status") == "ok", r.text[:200])
            check("health leak-free", not check_no_secrets(r.text, secrets), "secret in /health")
        except Exception as exc:
            check("health reachable", False, str(exc)[:200])

        # 4: /status non-sensitive shape.
        try:
            r = client.get(f"{base}/status", timeout=15)
            body = r.json()
            check("status 200", r.status_code == 200, r.text[:200])
            check("status has x_status", body.get("x_status") in {
                "CONNECTED", "INVALID_SESSION", "RATE_LIMITED",
                "X_UNAVAILABLE", "CONFIG_ERROR", "NOT_CONFIGURED"}, r.text[:200])
            blob = json.dumps(body).lower()
            check("status leak-free",
                  not any(k in blob for k in ("auth_token", "ct0", "cookie")) and
                  not check_no_secrets(r.text, secrets), "sensitive data in /status")
        except Exception as exc:
            check("status reachable", False, str(exc)[:200])

        # 5: unauthenticated MCP rejected.
        try:
            r = client.post(f"{base}/mcp", json={"jsonrpc": "2.0", "id": 1,
                                                 "method": "tools/list", "params": {}},
                            headers={"Accept": "application/json, text/event-stream"}, timeout=15)
            check("mcp rejects anonymous", r.status_code in (401, 403, 503), f"got {r.status_code}")
        except Exception as exc:
            check("mcp rejects anonymous", False, str(exc)[:200])

        # 6-8: authenticated handshake + live tool enumeration.
        try:
            session = mcp_handshake(client, base, token)
            headers = {"Authorization": f"Bearer {token}",
                       "Accept": "application/json, text/event-stream",
                       "Content-Type": "application/json", "mcp-session-id": session}
            r = client.post(f"{base}/mcp",
                            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                            headers=headers, timeout=60)
            check("tools/list 200", r.status_code == 200, f"got {r.status_code} {r.text[:200]}")
            names: list[str] = []
            if r.status_code == 200:
                names = [t["name"] for t in
                         (_message_with_id(parse_mcp_messages(r.text), 2) or {})
                         .get("result", {}).get("tools", [])]
                check("tools non-empty", len(names) > 0, "empty tool list")
                for must_have in ("search", "get_user", "get_tweet", "post_tweet"):
                    check(f"tool present: {must_have}", must_have in names, f"{len(names)} tools")
                print(f"      tool count (live): {len(names)}")
                check("tools leak-free", not check_no_secrets(r.text, secrets), "secret in tools/list")

            # 9: /tools diagnostic agrees (gateway-level enumeration).
            r2 = client.get(f"{base}/tools", headers={"Authorization": f"Bearer {token}"}, timeout=30)
            if r2.status_code == 200:
                diag = r2.json()
                check("diagnostic tool count matches",
                      diag.get("count") == len(names), f"diag={diag.get('count')} live={len(names)}")
            else:
                check("diagnostic /tools", False, f"got {r2.status_code}")

            # 10 (opt-in): real read-only X calls with content assertions, so a
            # green discovery result can never mask a broken call path.
            if args.live:
                if not names:
                    check("live tool calls skipped", False, "no tools enumerated")
                else:
                    _live_call(client, base, headers, "get_user",
                               {"username": "nasa"}, check, _validate_get_user)
                    _live_call(client, base, headers, "search_users",
                               {"query": "nasa", "limit": 3}, check, _validate_search_users)
        except AssertionError as exc:
            check("mcp handshake", False, str(exc)[:300])
        except Exception as exc:
            check("mcp handshake", False, str(exc)[:300])

        # 11: admin endpoints require the separate admin token.
        try:
            r = client.get(f"{base}/admin/accounts",
                           headers={"Authorization": f"Bearer {token}"}, timeout=15)
            check("admin rejects mcp token", r.status_code in (401, 403), f"got {r.status_code}")
            if admin and admin != token:
                r = client.get(f"{base}/admin/accounts",
                               headers={"Authorization": f"Bearer {admin}"}, timeout=15)
                check("admin accepts admin token", r.status_code == 200, f"got {r.status_code}")
        except Exception as exc:
            check("admin gating", False, str(exc)[:200])

    print(f"\n{'ALL CHECKS PASSED' if not failures else f'{len(failures)} CHECK(S) FAILED'}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
