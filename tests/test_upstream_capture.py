"""Admin-gated upstream GraphQL write-response capture.

Covers the diagnostic hook (off by default, bounded, secret-redacted,
pass-through) and the three admin routes that gate it. No network: the hook
tests stub the spectre writer singleton, and the route tests exercise auth
and CSRF only.
"""

from __future__ import annotations

import json
import os

import pytest

from app import upstream_capture

ADMIN = {"Authorization": f"Bearer {os.environ['ADMIN_TOKEN']}"}
MCP = {"Authorization": f"Bearer {os.environ['MCP_ACCESS_TOKEN']}"}


class _StubWriter:
    """Deterministic stand-in for spectre's writer singleton."""

    def __init__(self, results=None, exc=None):
        self.results = list(results or [])
        self.exc = exc
        self.calls = []

    async def _post(self, operation, variables, features=None, field_toggles=None):
        self.calls.append((operation, variables, features, field_toggles))
        if self.exc is not None:
            raise self.exc
        return self.results.pop(0)


# ── capture state (no spectre) ────────────────────────────────────────────

def test_off_by_default_records_nothing():
    state = upstream_capture.CaptureState()
    state.record("createBookmarkFolder", {"folder_name": "x"}, {"status": "created"})
    assert state.snapshot() == []
    assert state.summary() == {"enabled": False, "operations": None, "count": 0}


def test_enable_records_operation_variables_response():
    state = upstream_capture.CaptureState()
    state.enable()
    state.record("createBookmarkFolder", {"folder_name": "x"}, {"status": "created"})
    entries = state.snapshot()
    assert len(entries) == 1
    assert entries[0]["operation"] == "createBookmarkFolder"
    assert entries[0]["variables"] == {"folder_name": "x"}
    assert entries[0]["response"] == {"status": "created"}
    assert "captured_at" in entries[0]


def test_operations_filter_restricts_capture():
    state = upstream_capture.CaptureState()
    state.enable(["createBookmarkFolder"])
    state.record("createBookmarkFolder", {}, {})
    state.record("FollowUser", {}, {})
    assert [e["operation"] for e in state.snapshot()] == ["createBookmarkFolder"]


def test_ring_buffer_caps_and_drops_oldest():
    state = upstream_capture.CaptureState(capacity=3)
    state.enable()
    for i in range(5):
        state.record("op", {"i": i}, {"ok": True})
    entries = state.snapshot()
    assert len(entries) == 3
    # Newest first; the two oldest entries (0 and 1) were dropped.
    assert [e["variables"]["i"] for e in entries] == [4, 3, 2]


def test_disable_stops_recording_and_clears():
    state = upstream_capture.CaptureState()
    state.enable()
    state.record("op", {}, {})
    assert state.summary()["count"] == 1
    state.disable()
    assert state.snapshot() == []
    assert state.summary() == {"enabled": False, "operations": None, "count": 0}
    state.record("op", {}, {})
    assert state.snapshot() == []


def test_entry_shape_stores_only_parsed_dicts_and_redacts_values():
    """A stored entry has no transport/auth fields and secret values are scrubbed."""
    state = upstream_capture.CaptureState()
    state.enable()
    secret = "abcde12345" * 5  # 50 chars -> long-token scrubber fires
    state.record("FollowUser", {"user_id": "123"}, {"data": {"token": secret}})
    entry = state.snapshot()[0]
    assert set(entry.keys()) == {"operation", "variables", "response", "captured_at"}
    dumped = json.dumps(entry)
    assert secret not in dumped
    assert "[redacted]" in dumped
    # Headers, auth tokens and transport bodies are never part of an entry.
    for forbidden in ("headers", "cookies", "authorization", "bearer", "auth_token", "ct0"):
        assert forbidden not in dumped.lower()


def test_redact_value_applies_shared_redaction_to_nested_strings():
    secret = "x" * 40
    out = upstream_capture._redact_value({
        "auth_token": secret,
        "nested": ["Bearer " + secret, {"ct0": "y" * 160}],
    })
    dumped = json.dumps(out)
    assert secret not in dumped
    assert "y" * 160 not in dumped


# ── hook (stubbed writer) ──────────────────────────────────────────────────

def _fresh_hook_state(monkeypatch):
    state = upstream_capture.CaptureState()
    monkeypatch.setattr(upstream_capture, "_state", state)
    monkeypatch.setattr(upstream_capture, "_hook_installed", False)
    return state


async def test_hook_off_by_default_records_nothing(monkeypatch):
    state = _fresh_hook_state(monkeypatch)
    stub = _StubWriter(results=[{"ok": True}])
    monkeypatch.setattr("spectre.server._get_writer", lambda: stub)
    upstream_capture.install_hook()

    result = await stub._post("FollowUser", {})
    assert result == {"ok": True}
    assert state.snapshot() == []


async def test_hook_records_and_preserves_return_value(monkeypatch):
    state = _fresh_hook_state(monkeypatch)
    expected = {"status": "created", "folder_id": None}
    stub = _StubWriter(results=[expected])
    monkeypatch.setattr("spectre.server._get_writer", lambda: stub)
    upstream_capture.enable(["createBookmarkFolder"])

    result = await stub._post("createBookmarkFolder", {"name": "x"})
    assert result == expected  # return value unchanged
    entries = state.snapshot()
    assert len(entries) == 1
    assert entries[0]["operation"] == "createBookmarkFolder"
    assert entries[0]["variables"] == {"name": "x"}
    assert entries[0]["response"] == expected


async def test_hook_propagates_exception_unchanged(monkeypatch):
    state = _fresh_hook_state(monkeypatch)

    class Boom(Exception):
        pass

    stub = _StubWriter(exc=Boom("nope"))
    monkeypatch.setattr("spectre.server._get_writer", lambda: stub)
    upstream_capture.enable()

    with pytest.raises(Boom, match="nope"):
        await stub._post("FollowUser", {"user_id": "1"})
    # Errors are deliberately not recorded: they already surface to the caller.
    assert state.snapshot() == []


# ── admin routes (auth + CSRF) ─────────────────────────────────────────────

def test_upstream_capture_routes_reject_anonymous(client):
    client.cookies.clear()
    for method, path, body in (
        ("GET", "/admin/api/upstream-capture", None),
        ("POST", "/admin/api/upstream-capture", {"operations": []}),
        ("DELETE", "/admin/api/upstream-capture", None),
    ):
        resp = client.request(method, path, json=body)
        assert resp.status_code == 401, f"{method} {path} -> {resp.status_code}"


def test_upstream_capture_routes_reject_mcp_token(client):
    client.cookies.clear()
    for method, path, body in (
        ("GET", "/admin/api/upstream-capture", None),
        ("POST", "/admin/api/upstream-capture", {"operations": []}),
        ("DELETE", "/admin/api/upstream-capture", None),
    ):
        resp = client.request(method, path, headers=MCP, json=body)
        assert resp.status_code == 401, f"{method} {path} -> {resp.status_code}"


def test_upstream_capture_enable_requires_csrf_for_session_auth(client):
    client.cookies.clear()
    assert client.post("/admin/api/login",
                       json={"token": os.environ["ADMIN_TOKEN"]}).status_code == 200
    resp = client.post("/admin/api/upstream-capture", json={"operations": []})
    assert resp.status_code == 403
    client.cookies.clear()


def test_upstream_capture_lifecycle_and_response_shape(client):
    """Bearer-authenticated enable -> get -> delete returns consistent state."""
    client.cookies.clear()
    enable = client.post("/admin/api/upstream-capture", headers=ADMIN,
                         json={"operations": ["FollowUser"]})
    assert enable.status_code == 200, enable.text
    body = enable.json()
    assert body["enabled"] is True
    assert body["operations"] == ["FollowUser"]
    assert body["count"] == 0
    assert "cookie" not in enable.text.lower()
    assert os.environ["ADMIN_TOKEN"] not in enable.text

    listing = client.get("/admin/api/upstream-capture", headers=ADMIN)
    assert listing.status_code == 200, listing.text
    assert listing.json()["enabled"] is True
    assert listing.json()["entries"] == []
    assert "cookie" not in listing.text.lower()

    disable = client.delete("/admin/api/upstream-capture", headers=ADMIN)
    assert disable.status_code == 200, disable.text
    assert disable.json() == {"enabled": False, "operations": None, "count": 0}
    assert "cookie" not in disable.text.lower()

    # Leave capture off so no other session test observes an enabled flag.
    assert client.get("/admin/api/upstream-capture",
                      headers=ADMIN).json()["enabled"] is False
