"""Unit tests for the operator scripts' non-trivial helpers.

The scripts themselves are exercised against a live process (see
docs/invocation.md), but the parsing/validation logic that decides whether a
call path is healthy must be covered without a server: a discovery-only green
result must be provably unable to mask a broken call path.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name: str, relpath: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, relpath))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


smoke = _load("kxstrel_smoke_test", os.path.join("scripts", "smoke_test.py"))
probe = _load("kxstrel_live_probe", os.path.join("scripts", "live_mcp_probe.py"))


# ── smoke_test.py: response parsing ──────────────────────────────────────

def test_smoke_parses_sse_framing():
    body = (
        ": keepalive\n"
        "event: message\n"
        "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n"
        "\n"
        "event: message\n"
        "data: {\"jsonrpc\":\"2.0\",\"id\":3,\n"
        "data: \"result\":{\"content\":[]}}\n"
        "\n"
    )
    messages = smoke.parse_mcp_messages(body)
    assert [m["id"] for m in messages] == [2, 3]
    assert messages[1]["result"] == {"content": []}


def test_smoke_parses_plain_json_body():
    assert smoke.parse_mcp_messages('{"jsonrpc":"2.0","id":1,"result":{}}') == [
        {"jsonrpc": "2.0", "id": 1, "result": {}}]
    assert smoke.parse_mcp_messages("") == []
    assert smoke.parse_mcp_messages("not json at all") == []


def test_smoke_tool_result_payload_shapes():
    ok = {"jsonrpc": "2.0", "id": 3,
          "result": {"content": [{"type": "text", "text": "hello"}], "isError": False}}
    text, error = smoke.tool_result_payload(ok)
    assert text == "hello" and error is None

    # isError=true is still a well-formed envelope: the text is the error.
    err = {"jsonrpc": "2.0", "id": 3,
           "result": {"content": [{"type": "text", "text": "boom"}], "isError": True}}
    text, error = smoke.tool_result_payload(err)
    assert text == "boom" and error is None

    # Malformed envelopes are reported as errors, never silently accepted.
    for broken in (
        None,
        {"jsonrpc": "2.0", "id": 3, "error": {"code": -32000, "message": "nope"}},
        {"jsonrpc": "2.0", "id": 3, "result": {}},
        {"jsonrpc": "2.0", "id": 3, "result": {"content": []}},
        {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "image"}]}},
    ):
        text, error = smoke.tool_result_payload(broken)
        assert error, f"expected an envelope error for {broken!r}"
        assert text == ""


# ── smoke_test.py: --live content assertions ─────────────────────────────

class _FakeResponse:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    def __init__(self, response):
        self._response = response
        self.calls: list[dict] = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append({"url": url, "json": json})
        return self._response


def _envelope(payload: str, is_error: bool = False, request_id=None) -> str:
    body = {"jsonrpc": "2.0", "id": request_id,
            "result": {"content": [{"type": "text", "text": payload}], "isError": is_error}}
    return "event: message\ndata: " + json.dumps(body) + "\n\n"


def _run_live_call(response_text: str, status_code: int = 200, validate=None,
                   tool: str = "get_user"):
    results: list[tuple[str, bool, str]] = []

    def check(name, ok, detail=""):
        results.append((name, ok, detail))

    client = _FakeClient(_FakeResponse(status_code, response_text))
    request_id = None
    smoke._live_call(client, "http://x", {}, tool, {}, check,
                     validate or smoke._validate_get_user)
    # the request id is generated inside _live_call; recover it from the request
    request_id = client.calls[0]["json"]["id"]
    return results, client, request_id


def test_smoke_live_accepts_real_get_user_content():
    payload = json.dumps({"id": 12345, "username": "nasa", "display_name": "NASA"})
    # Re-encode with the id the caller will use (the helper generates one).
    results, client, rid = _run_live_call(_envelope(payload, request_id=None))
    # The fake body carries id=None; _message_with_id falls back to the last
    # message, so the envelope is still found and validated.
    assert results and results[0][1] is True, results


def test_smoke_live_fails_on_empty_payload():
    results, _, _ = _run_live_call(_envelope(""))
    assert results and results[0][1] is False
    assert "empty" in results[0][2]


def test_smoke_live_fails_on_shape_mismatch():
    results, _, _ = _run_live_call(_envelope(json.dumps({"error": "User @nasa not found"})))
    assert results and results[0][1] is False
    assert "missing" in results[0][2] or "expected" in results[0][2]


def test_smoke_live_fails_on_iserror_result():
    results, _, _ = _run_live_call(_envelope("tool exploded", is_error=True))
    assert results and results[0][1] is False
    assert "isError" in results[0][2]


def test_smoke_live_fails_on_malformed_envelope():
    results, _, _ = _run_live_call(json.dumps({"jsonrpc": "2.0", "id": 3, "result": {}}))
    assert results and results[0][1] is False
    assert "content" in results[0][2]


def test_smoke_live_fails_on_non_200():
    results, _, _ = _run_live_call("nope", status_code=500)
    assert results and results[0][1] is False
    assert "500" in results[0][2]


def test_smoke_validators():
    assert smoke._validate_get_user('{"id": 1, "username": "nasa"}') == (True, "")
    ok, detail = smoke._validate_get_user('{"id": 1}')
    assert ok is False and "username" in detail
    assert smoke._validate_search_users('[{"id": 1, "username": "nasa"}]') == (True, "")
    ok, detail = smoke._validate_search_users("[]")
    assert ok is False and "non-empty" in detail
    ok, _ = smoke._validate_search_users('{"users": [{"id": 1}]}')
    assert ok is True
    ok, _ = smoke._validate_search_users("not json")
    assert ok is False


def test_smoke_search_users_accepts_nested_list():
    payload = json.dumps({"data": [{"id": 7, "username": "nasa"}]})
    results, _, _ = _run_live_call(_envelope(payload, request_id=None),
                                   validate=smoke._validate_search_users,
                                   tool="search_users")
    assert results and results[0][1] is True


# ── live_mcp_probe.py ────────────────────────────────────────────────────

def test_probe_parse_framing_labels():
    assert probe.parse_mcp_response('{"jsonrpc":"2.0","id":1,"result":{}}',
                                    "application/json") == (
        [{"jsonrpc": "2.0", "id": 1, "result": {}}], "json")
    msgs, framing = probe.parse_mcp_response(
        "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n",
        "text/event-stream")
    assert framing == "sse" and msgs[-1]["id"] == 1
    assert probe.parse_mcp_response("", "text/event-stream") == ([], "empty")
    assert probe.parse_mcp_response("garbage", "application/json") == ([], "unparsed")


def test_probe_check_tool_result():
    well_formed = {"jsonrpc": "2.0", "id": 3, "result": {
        "content": [{"type": "text", "text": "x"}], "isError": False}}
    ok, detail = probe.check_tool_result(well_formed)
    assert ok and detail == "ok"
    ok, detail = probe.check_tool_result({"jsonrpc": "2.0", "id": 3, "result": {
        "content": [{"type": "text", "text": "boom"}], "isError": True}})
    assert ok and "upstream tool error" in detail
    for broken in (None, {"result": {}}, {"result": {"content": []}},
                   {"result": {"content": [{"type": "image"}]}}):
        ok, _ = probe.check_tool_result(broken)
        assert ok is False, broken
    ok, _ = probe.check_tool_result(
        {"jsonrpc": "2.0", "id": 3, "error": {"code": -32601, "message": "no tool"}})
    assert ok is True  # a JSON-RPC error is a reported outcome, not a broken shape


def test_probe_upstream_error_hint_reports_not_pretends():
    assert probe._upstream_error_hint('{"error": "User @nasa not found"}').startswith(
        "tool payload reports")
    assert "empty list" in probe._upstream_error_hint("[]")
    assert "empty" in probe._upstream_error_hint("   ")
    assert probe._upstream_error_hint('{"id": 1, "username": "nasa"}') is None
    assert probe._upstream_error_hint('[{"id": 1}]') is None


def test_probe_redacts_authorization_header():
    headers = {"Authorization": "Bearer super-secret-token", "Accept": "application/json"}
    redacted = probe._redact_headers(headers)
    assert redacted["Authorization"] == "Bearer [redacted]"
    assert "super-secret-token" not in json.dumps(redacted)
    assert redacted["Accept"] == "application/json"


def test_probe_cleanup_reports_no_proxy_honestly(tmp_path, capsys):
    out = tmp_path / "probe.json"
    assert probe.cleanup(str(out)) == 0
    captured = capsys.readouterr().out
    assert "no proxy processes were started by this script" in captured
    assert "nothing to terminate" in captured


def test_probe_cleanup_only_targets_recorded_pids(tmp_path, capsys):
    out = tmp_path / "probe.json"
    out.write_text(json.dumps({probe.SPAWNED_KEY: []}), encoding="utf-8")
    assert probe.cleanup(str(out)) == 0
    assert "no proxy processes were started" in capsys.readouterr().out


def test_probe_requires_a_token(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("MCP_ACCESS_TOKEN", raising=False)
    assert probe.main(["--base-url", "http://127.0.0.1:1",
                       "--out", str(tmp_path / "p.json")]) == 2
    assert "no token" in capsys.readouterr().err


def test_probe_rejects_bad_args_json(tmp_path, capsys):
    code = probe.main(["--base-url", "http://127.0.0.1:1", "--token", "t" * 40,
                       "--args-json", "{not json", "--out", str(tmp_path / "p.json")])
    assert code == 2
    assert "args-json" in capsys.readouterr().err


@pytest.mark.parametrize("value", ['["a"]', '"str"', "42"])
def test_probe_rejects_non_object_args(tmp_path, value, capsys):
    code = probe.main(["--base-url", "http://127.0.0.1:1", "--token", "t" * 40,
                       "--args-json", value, "--out", str(tmp_path / "p.json")])
    assert code == 2
