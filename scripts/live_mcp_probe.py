#!/usr/bin/env python3
"""End-to-end MCP Streamable-HTTP probe with a complete, readable transcript.

What it does, in order:
  1. POST initialize
  2. POST notifications/initialized
  3. POST tools/list
  4. (with --live) POST tools/call for --tool / --args-json

Every request body is serialized once to a temp file and posted from those
exact bytes (the `curl --data-binary @file` equivalent) so no shell quoting
can corrupt the JSON. No subprocess and no shell are involved in the primary
path — the whole exchange goes through httpx.

The COMPLETE exchange (request method/path/headers/body, response
status/headers/body, timings, parsed JSON-RPC messages, diagnostics) is
persisted to --out, so an operator can read back exactly what happened.
stderr is never suppressed: diagnostics are printed AND recorded.

Exit codes:
  0  handshake + tools/list succeeded; with --live either a well-formed
     tool result envelope or a *reported* upstream tool error
  1  protocol/shape failure (handshake, tools/list, malformed envelope)
  2  usage/configuration error (missing token etc.)

Usage:
    python scripts/live_mcp_probe.py --base-url http://localhost:8000
    MCP_ACCESS_TOKEN=... python scripts/live_mcp_probe.py --base-url https://host --live
    python scripts/live_mcp_probe.py --base-url http://localhost:8000 --live \
        --tool search --args-json '{"query": "nasa", "limit": 1}' --debug
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone

import httpx

DEFAULT_TOOL = "get_user"
DEFAULT_ARGS = {"username": "nasa"}
PROTOCOL_VERSION = "2025-06-18"
DEFAULT_OUT = "live_mcp_probe.json"
CLIENT_NAME = "kxstrel-live-probe"
CLIENT_VERSION = "1.0"

# Proxy processes this script would have to stop, if it ever started any.
# The primary path starts none: it speaks JSON-RPC directly. The record is
# persisted in --out so `--cleanup` can act on a previous run's own children
# (and never on anything this script did not start).
SPAWNED_KEY = "spawned_processes"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Transcript:
    """Accumulates the full exchange plus our own diagnostics."""

    def __init__(self, debug: bool):
        self.debug = debug
        self.started_at = _utcnow()
        self.base_url = ""
        self.exchanges: list[dict] = []
        self.diagnostics: list[str] = []
        self.spawned_processes: list[dict] = []
        self.result: dict = {}

    def note(self, message: str, *, error: bool = False) -> None:
        """Print to stderr (never suppressed) and record in the transcript."""
        self.diagnostics.append({"ts": _utcnow(), "message": message, "error": error})
        print(message, file=sys.stderr)

    def add_exchange(self, entry: dict) -> None:
        self.exchanges.append(entry)
        if self.debug:
            print(_format_exchange(entry), file=sys.stderr)

    def write(self, path: str) -> None:
        payload = {
            "probe": "live_mcp_probe",
            "started_at": self.started_at,
            "finished_at": _utcnow(),
            "base_url": self.base_url,
            "exchanges": self.exchanges,
            "diagnostics": self.diagnostics,
            "result": self.result,
            SPAWNED_KEY: self.spawned_processes,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=False)
            fh.write("\n")


def _redact_headers(headers: dict) -> dict:
    out = {}
    for key, value in headers.items():
        if key.lower() == "authorization":
            scheme = value.split(" ", 1)[0] if " " in value else "Bearer"
            out[key] = f"{scheme} [redacted]"
        else:
            out[key] = value
    return out


def _format_exchange(entry: dict) -> str:
    lines = [
        f"--- {entry['step']} ---",
        f"> {entry['method']} {entry['path']}",
        f"> headers: {json.dumps(entry['request_headers'], sort_keys=True)}",
        f"> body: {entry['request_body']}",
        f"< status: {entry['status']} ({entry.get('elapsed_ms', 0)}ms)",
        f"< headers: {json.dumps(entry['response_headers'], sort_keys=True)}",
        f"< body: {entry['response_body']}",
    ]
    return "\n".join(lines)


def _post(client: httpx.Client, url: str, path: str, body: dict, headers: dict,
          step: str, tx: Transcript) -> tuple[httpx.Response, list[dict]]:
    """Serialize once, post the exact bytes, record everything.

    The body is written to a temp file and read back before posting: this is
    the byte-for-byte equivalent of `curl --data-binary @file` and removes
    any possibility of shell/quoting corruption."""
    raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(prefix="kxstrel-probe-", suffix=".json",
                                         delete=False) as fh:
            fh.write(raw)
            tmp_path = fh.name
        with open(tmp_path, "rb") as fh:
            payload = fh.read()  # byte-exact request body
        started = time.monotonic()
        resp = client.post(url, content=payload, headers=headers)
        elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    safe_headers = _redact_headers(dict(headers))
    messages, framing = parse_mcp_response(resp.text, resp.headers.get("content-type", ""))
    tx.add_exchange({
        "step": step,
        "method": "POST",
        "path": path,
        "url": url,  # never includes the token: it lives in the header only
        "request_headers": safe_headers,
        "request_body_sha256": digest,
        "request_body": raw.decode("utf-8"),
        "status": resp.status_code,
        "response_headers": dict(resp.headers),
        "response_body": resp.text,
        "elapsed_ms": elapsed_ms,
        "response_framing": framing,
        "response_messages": messages,
    })
    return resp, messages


def parse_mcp_response(text: str, content_type: str) -> tuple[list[dict], str]:
    """Decode JSON-RPC messages from SSE (`event: message` / `data:` lines)
    or plain JSON. Returns (messages, framing)."""
    if not text.strip():
        return [], "empty"
    if "text/event-stream" not in (content_type or "").lower():
        try:
            return [json.loads(text.strip())], "json"
        except json.JSONDecodeError:
            return [], "unparsed"

    messages: list[dict] = []
    data_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith(":"):
            continue  # SSE comment/keepalive
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
            continue
        if not line.strip():
            if data_lines:
                blob = "\n".join(data_lines)
                data_lines = []
                try:
                    messages.append(json.loads(blob))
                except json.JSONDecodeError:
                    continue
            continue
        # `event:`/`id:`/`retry:` lines carry no JSON-RPC payload
    if data_lines:
        try:
            messages.append(json.loads("\n".join(data_lines)))
        except json.JSONDecodeError:
            pass
    return messages, "sse"


def _find_message(messages: list[dict], request_id) -> dict | None:
    for msg in messages:
        if msg.get("id") == request_id:
            return msg
    return messages[-1] if messages else None


def _json_or_none(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def _upstream_error_hint(payload: str) -> str | None:
    """Detect a tool payload that carries an upstream problem.

    Spectre answers some failures with a *successful* MCP envelope whose
    text is `{"error": "..."}` (e.g. no X account configured). That is an
    upstream tool error and must be reported as such, not as success."""
    stripped = payload.strip()
    if not stripped:
        return "tool payload is empty"
    parsed = _json_or_none(stripped)
    if isinstance(parsed, dict) and parsed.get("error"):
        return f"tool payload reports: {str(parsed['error'])[:200]}"
    if isinstance(parsed, list) and not parsed:
        return ("tool payload is an empty list (no data returned; the X session may "
                "be unconfigured or the query matched nothing)")
    return None


def check_tool_result(message: dict | None) -> tuple[bool, str]:
    """Validate the MCP tool-result envelope. Returns (well_formed, detail)."""
    if message is None:
        return False, "no JSON-RPC message in the response"
    if "error" in message:
        return True, f"JSON-RPC error (upstream/rpc): {json.dumps(message['error'])[:300]}"
    result = message.get("result")
    if not isinstance(result, dict):
        return False, f"missing result object: {json.dumps(message)[:300]}"
    content = result.get("content")
    if not isinstance(content, list) or not content:
        return False, f"result.content must be a non-empty list: {json.dumps(result)[:300]}"
    first = content[0]
    if not isinstance(first, dict) or "text" not in first:
        return False, f"result.content[0].text missing: {json.dumps(first)[:300]}"
    if result.get("isError") is True:
        return True, f"upstream tool error: {str(first.get('text'))[:300]}"
    return True, "ok"


def cleanup(path: str) -> int:
    """Terminate proxy processes a previous run of THIS script recorded."""
    recorded: list[dict] = []
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                recorded = json.load(fh).get(SPAWNED_KEY) or []
        except Exception as exc:
            print(f"cleanup: could not read {path}: {exc}", file=sys.stderr)
            return 1
    if not recorded:
        print("cleanup: no proxy processes were started by this script "
              "(primary path is plain JSON-RPC over POST /mcp — no npx, no proxy), "
              f"and no local callback ports were allocated; nothing to terminate "
              f"(record checked: {path}).")
        return 0
    failures = 0
    for entry in recorded:
        pid = int(entry.get("pid") or 0)
        cmd = entry.get("cmd") or "?"
        if pid <= 0:
            continue
        try:
            if os.name == "nt":
                os.system(f"taskkill /PID {pid} /T /F >NUL 2>&1")
            else:
                os.kill(pid, 15)
            print(f"cleanup: terminated proxy pid={pid} cmd={cmd}")
        except Exception as exc:
            failures += 1
            print(f"cleanup: could not terminate pid={pid} ({exc})", file=sys.stderr)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
        payload[SPAWNED_KEY] = []
        payload.setdefault("cleanup", []).append({
            "ts": _utcnow(), "terminated": len(recorded) - failures, "failed": failures,
        })
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
    return 0 if not failures else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="End-to-end MCP probe with full transcript")
    parser.add_argument("--base-url", default=os.environ.get("KXSTREL_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--token", default="", help="MCP bearer token (default: $MCP_ACCESS_TOKEN)")
    parser.add_argument("--tool", default=DEFAULT_TOOL, help=f"tool for --live (default {DEFAULT_TOOL})")
    parser.add_argument("--args-json", default="",
                        help=f"tool arguments as JSON (default {json.dumps(DEFAULT_ARGS)})")
    parser.add_argument("--out", default=DEFAULT_OUT, help="transcript file to write")
    parser.add_argument("--debug", action="store_true",
                        help="dump the full HTTP exchange to stderr (Authorization redacted)")
    parser.add_argument("--live", action="store_true", help="also perform a real tools/call")
    parser.add_argument("--cleanup", action="store_true",
                        help="terminate proxies recorded by a previous run of this script")
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args(argv)

    if args.cleanup:
        return cleanup(args.out)

    token = args.token or os.environ.get("MCP_ACCESS_TOKEN", "")
    if not token:
        print("error: no token (pass --token or set MCP_ACCESS_TOKEN)", file=sys.stderr)
        return 2
    try:
        tool_args = json.loads(args.args_json) if args.args_json else dict(DEFAULT_ARGS)
    except json.JSONDecodeError as exc:
        print(f"error: --args-json is not valid JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(tool_args, dict):
        print("error: --args-json must be a JSON object", file=sys.stderr)
        return 2

    base = args.base_url.rstrip("/")
    url = f"{base}/mcp"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    tx = Transcript(debug=args.debug)
    tx.started_at = _utcnow()
    tx.base_url = base

    def finish(code: int) -> int:
        tx.result["exit_code"] = code
        tx.write(args.out)
        print(f"transcript: {os.path.abspath(args.out)}")
        return code

    with httpx.Client(timeout=args.timeout, follow_redirects=False) as client:
        # 1. initialize
        init = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION}},
        }
        resp, messages = _post(client, url, "/mcp", init, headers, "initialize", tx)
        if resp.status_code != 200:
            tx.note(f"FAIL initialize: HTTP {resp.status_code} {resp.text[:300]}", error=True)
            return finish(1)
        message = _find_message(messages, 1)
        if not message or "result" not in message:
            tx.note(f"FAIL initialize: no result in {resp.text[:300]}", error=True)
            return finish(1)
        server_info = message["result"].get("serverInfo", {})
        session_id = resp.headers.get("mcp-session-id", "")
        tx.note(f"initialize ok: server={server_info.get('name')} "
                f"version={server_info.get('version')} session={session_id or '(none)'}")
        if not session_id:
            tx.note("WARN: no mcp-session-id header; continuing statelessly")
        session_headers = dict(headers)
        if session_id:
            session_headers["mcp-session-id"] = session_id

        # 2. notifications/initialized (no id, per spec)
        notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        resp, _ = _post(client, url, "/mcp", notif, session_headers,
                        "notifications/initialized", tx)
        if resp.status_code not in (200, 202, 204):
            tx.note(f"FAIL notifications/initialized: HTTP {resp.status_code} {resp.text[:200]}",
                    error=True)
            return finish(1)

        # 3. tools/list
        listing = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        resp, messages = _post(client, url, "/mcp", listing, session_headers, "tools/list", tx)
        if resp.status_code != 200:
            tx.note(f"FAIL tools/list: HTTP {resp.status_code} {resp.text[:300]}", error=True)
            return finish(1)
        message = _find_message(messages, 2)
        tools = (message or {}).get("result", {}).get("tools", []) if message else []
        names = [t.get("name") for t in tools]
        if not names:
            tx.note(f"FAIL tools/list: empty tool list ({resp.text[:300]})", error=True)
            return finish(1)
        tx.result["tool_count"] = len(names)
        tx.note(f"tools/list ok: {len(names)} tools")

        # 4. tools/call (opt-in)
        if not args.live:
            tx.note("tools/call skipped: pass --live to perform a real tool call")
            tx.result["tool_call"] = "skipped"
            return finish(0)

        if args.tool not in names:
            tx.note(f"FAIL tools/call: tool '{args.tool}' is not in the server's tool list",
                    error=True)
            return finish(1)
        call = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": args.tool, "arguments": tool_args}}
        resp, messages = _post(client, url, "/mcp", call, session_headers, "tools/call", tx)
        if resp.status_code != 200:
            tx.note(f"FAIL tools/call HTTP {resp.status_code}: {resp.text[:300]}", error=True)
            return finish(1)
        message = _find_message(messages, 3)
        well_formed, detail = check_tool_result(message)
        if not well_formed:
            tx.note(f"FAIL tools/call envelope: {detail}", error=True)
            return finish(1)
        payload = ""
        if message and isinstance(message.get("result"), dict):
            content = message["result"].get("content") or []
            payload = str(content[0].get("text", "")) if content else ""
        is_error = bool(message.get("result", {}).get("isError")) if message else False
        hint = _upstream_error_hint(payload)
        tx.result["tool_call"] = {
            "tool": args.tool, "arguments": tool_args,
            "is_error": is_error, "detail": detail, "payload_preview": payload[:2000],
            "upstream_error": hint,
        }
        if is_error:
            tx.note(f"UPSTREAM TOOL ERROR for '{args.tool}': {detail}")
            tx.note("handshake + tools/list succeeded and the call path is proven "
                    "(the server answered with a well-formed MCP envelope).")
            return finish(0)
        if hint:
            tx.note(f"UPSTREAM TOOL ERROR for '{args.tool}': {hint}")
            tx.note("handshake + tools/list succeeded and the call path is proven "
                    "(well-formed MCP envelope, HTTP 200); the upstream X backend "
                    "reported a problem.")
            return finish(0)
        tx.note(f"tools/call ok: '{args.tool}' returned {len(payload)} chars of content")
        return finish(0)


if __name__ == "__main__":
    sys.exit(main())
