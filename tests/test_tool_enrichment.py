"""Result enrichment: handing the caller an id the upstream result omits.

Spectre 1.0.3's `schedule_tweet` discards the CreateScheduledTweet response, so
its result carries no id and `edit_scheduled_tweet` / `delete_scheduled_tweet`
(which require `scheduled_id` / `tweet_id`) cannot be driven from it. The
gateway recovers the id from the tool's own listing (`get_scheduled_tweets`)
and appends it, marked as gateway-recovered.

Deterministic by construction: the writer is stubbed (no X traffic) and the
tool under test is a local stand-in that returns exactly the JSON object
spectre's writer returns — a `-> str` tool, so fastmcp wraps it the same way
(text block = the JSON, styled content = `{"result": "<that JSON>"}`).
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.tools.base import ToolResult

from app import tool_middleware
from app.db import AccountStore
from app.models import GatewayState

TEXT = "gateway enrichment fixture"
SCHEDULED_ID = "2099518124605526016"
OTHER_SCHEDULED_ID = "2099518124605526999"
# One fixed instant: what `schedule_tweet` reports is SECONDS, what
# `get_scheduled_tweets` lists is MILLISECONDS.
EXECUTE_AT_SECONDS = 1811851200
EXECUTE_AT_MS = EXECUTE_AT_SECONDS * 1000
EXECUTE_AT_ISO = datetime.fromtimestamp(
    EXECUTE_AT_SECONDS, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _FakeWriter:
    """Stands in for spectre's writer: only the listing call is needed."""

    def __init__(self, listing=None, error=None, stall=0.0):
        self.listing = listing
        self.error = error
        self.stall = stall
        self.calls = 0

    async def get_scheduled_tweets(self):
        self.calls += 1
        if self.stall:
            await asyncio.sleep(self.stall)
        if self.error is not None:
            raise self.error
        return self.listing


def _entry(text: str = TEXT, execute_at: int = EXECUTE_AT_MS,
           scheduled_id: str = SCHEDULED_ID) -> dict:
    return {"scheduled_id": scheduled_id, "text": text, "execute_at": execute_at,
            "state": "Scheduled"}


def _make_server(with_timestamp: bool = True) -> FastMCP:
    server = FastMCP("enrichment-probe")

    @server.tool
    async def schedule_tweet(text: str, execute_at: str,
                             reply_to: int | None = None) -> str:
        # Same shape as spectre 1.0.3: the create response is thrown away and
        # only these fields survive — no id anywhere.
        payload = {"status": "scheduled", "execute_at": execute_at}
        if with_timestamp:
            payload["execute_at_timestamp"] = EXECUTE_AT_SECONDS
        return json.dumps(payload)

    return server


async def _probe(tmp_path, monkeypatch, *, listing=None, error=None, stall=0.0,
                 disabled=False, with_timestamp=True, db="enrich.db"):
    """A FastMCP server with the gateway middleware attached and the writer
    stubbed. Returns (server, store, writer)."""
    server = _make_server(with_timestamp=with_timestamp)
    store = AccountStore(f"sqlite:///{tmp_path / db}")
    await store.connect()
    await store.init_schema()
    if disabled:
        await store.set_tool_flag("schedule_tweet", False)
    state = GatewayState()
    state.tool_names = ["schedule_tweet"]
    assert tool_middleware.attach(server, store, state) is not None
    writer = _FakeWriter(listing=listing, error=error, stall=stall)
    monkeypatch.setattr(tool_middleware, "_get_writer", lambda: writer)
    return server, store, writer


async def _call(server):
    return await server.call_tool(
        "schedule_tweet", {"text": TEXT, "execute_at": EXECUTE_AT_ISO})


def _views(result) -> tuple[dict, dict]:
    """The JSON the caller sees, from both representations, parsed."""
    text_view = json.loads(result.content[0].text)
    structured_view = json.loads(result.structured_content["result"])
    assert text_view == structured_view, "text and structured views disagree"
    return text_view, structured_view


_UPSTREAM_KEYS = {"status", "execute_at", "execute_at_timestamp"}


def test_enricher_table_targets_only_schedule_tweet():
    """Enrichment is a deliberate, explicit list — not a general rewrite."""
    assert set(tool_middleware.TOOL_ENRICHERS) == {"schedule_tweet"}


async def test_enricher_adds_recovered_scheduled_id(tmp_path, monkeypatch):
    """Exactly one listing match -> the id is appended, with provenance, and
    every upstream field survives untouched."""
    server, store, writer = await _probe(tmp_path, monkeypatch,
                                         listing=[_entry()])
    result = await _call(server)
    text_view, _ = _views(result)

    assert text_view["scheduled_id"] == SCHEDULED_ID
    note = text_view["scheduled_id_note"]
    assert "get_scheduled_tweets" in note
    assert "not returned by the create call" in note
    assert text_view["status"] == "scheduled"
    assert text_view["execute_at"] == EXECUTE_AT_ISO
    assert text_view["execute_at_timestamp"] == EXECUTE_AT_SECONDS
    assert writer.calls == 1
    assert result.is_error is False


@pytest.mark.parametrize("listing", [
    pytest.param([], id="empty-listing"),
    pytest.param([_entry(text=TEXT + " (edited elsewhere)")], id="text-mismatch"),
    pytest.param([_entry(execute_at=EXECUTE_AT_MS + 60_000)], id="time-mismatch"),
])
async def test_enricher_leaves_result_unchanged_without_a_match(
        tmp_path, monkeypatch, listing):
    """Zero matches: nothing is added and nothing is rewritten."""
    server, _, _ = await _probe(tmp_path, monkeypatch, listing=listing)
    result = await _call(server)
    text_view, _ = _views(result)

    assert set(text_view) == _UPSTREAM_KEYS
    assert text_view["status"] == "scheduled"


async def test_enricher_refuses_to_guess_between_two_matches(tmp_path, monkeypatch):
    """Two candidates with the same text and time -> no id at all. A wrong id
    would be worse than a missing one (it targets someone else's tweet)."""
    server, _, _ = await _probe(tmp_path, monkeypatch, listing=[
        _entry(scheduled_id=SCHEDULED_ID),
        _entry(scheduled_id=OTHER_SCHEDULED_ID),
    ])
    result = await _call(server)
    text_view, _ = _views(result)

    assert set(text_view) == _UPSTREAM_KEYS
    assert SCHEDULED_ID not in result.content[0].text


async def test_enricher_failure_keeps_the_original_result_and_logs(
        tmp_path, monkeypatch, caplog):
    """The enricher raising must not fail the call, change the result, or go
    unrecorded."""
    server, store, writer = await _probe(tmp_path, monkeypatch,
                                         error=RuntimeError("upstream exploded"))
    caplog.set_level(logging.WARNING, logger="kxstrel-x-mcp.tools")

    result = await _call(server)  # no exception escapes
    text_view, _ = _views(result)

    assert set(text_view) == _UPSTREAM_KEYS
    assert result.is_error is False
    assert writer.calls == 1
    assert any("result enrichment failed" in message and "RuntimeError" in message
               for message in caplog.messages), caplog.messages
    # ...and the call itself is still recorded as successful.
    rows = await store.list_tool_usage(limit=10, tool="schedule_tweet")
    assert rows and rows[0]["ok"] is True


async def test_enricher_maps_seconds_to_milliseconds(tmp_path, monkeypatch):
    """schedule_tweet reports seconds, the listing reports milliseconds: only
    the converted value may match."""
    # A millisecond listing entry matches...
    server, _, _ = await _probe(tmp_path, monkeypatch, db="ms.db",
                                listing=[_entry(execute_at=EXECUTE_AT_MS)])
    text_view, _ = _views(await _call(server))
    assert text_view["scheduled_id"] == SCHEDULED_ID

    # ...and the same number read as bare seconds (which a naive comparison
    # against `execute_at_timestamp` would have accepted) does not.
    server, _, _ = await _probe(tmp_path, monkeypatch, db="s.db",
                                listing=[_entry(execute_at=EXECUTE_AT_SECONDS)])
    text_view, _ = _views(await _call(server))
    assert set(text_view) == _UPSTREAM_KEYS


async def test_enricher_falls_back_to_the_iso_argument(tmp_path, monkeypatch):
    """If the create result carries no epoch at all, the ISO argument the tool
    was called with is converted instead."""
    server, _, _ = await _probe(tmp_path, monkeypatch,
                                with_timestamp=False, listing=[_entry()])
    text_view, _ = _views(await _call(server))

    assert text_view["scheduled_id"] == SCHEDULED_ID
    assert text_view["execute_at"] == EXECUTE_AT_ISO


async def test_enricher_timeout_keeps_the_original_result(tmp_path, monkeypatch):
    """A listing call that never answers is abandoned, not waited on."""
    monkeypatch.setattr(tool_middleware, "_ENRICH_TIMEOUT_SECONDS", 0.05)
    server, _, writer = await _probe(tmp_path, monkeypatch,
                                     listing=[_entry()], stall=30.0)

    text_view, _ = _views(await _call(server))
    assert set(text_view) == _UPSTREAM_KEYS
    assert writer.calls == 1


async def test_enrichment_skips_failed_results(monkeypatch):
    """A call that failed (isError) is never enriched, even when the payload
    would otherwise qualify."""
    monkeypatch.setattr(tool_middleware, "_get_writer",
                        lambda: _FakeWriter(listing=[_entry()]))
    payload = json.dumps({"status": "scheduled", "execute_at": EXECUTE_AT_ISO,
                          "execute_at_timestamp": EXECUTE_AT_SECONDS})
    result = ToolResult(content=payload, structured_content={"result": payload},
                        is_error=True)

    returned = await tool_middleware.enrich_result(
        "schedule_tweet", {"text": TEXT, "execute_at": EXECUTE_AT_ISO}, result)

    assert returned is result
    assert set(json.loads(result.content[0].text)) == _UPSTREAM_KEYS


async def test_enrichment_handles_a_dict_payload(monkeypatch):
    """Defensive: should a later spectre pin return the payload as a dict
    instead of a JSON string, both representations are still rewritten to
    carry the same object."""
    monkeypatch.setattr(tool_middleware, "_get_writer",
                        lambda: _FakeWriter(listing=[_entry()]))
    payload = {"status": "scheduled", "execute_at": EXECUTE_AT_ISO,
               "execute_at_timestamp": EXECUTE_AT_SECONDS}
    result = ToolResult(content=json.dumps(payload), structured_content=dict(payload))

    await tool_middleware.enrich_result(
        "schedule_tweet", {"text": TEXT, "execute_at": EXECUTE_AT_ISO}, result)

    assert json.loads(result.content[0].text)["scheduled_id"] == SCHEDULED_ID
    assert result.structured_content["scheduled_id"] == SCHEDULED_ID
    assert result.structured_content["status"] == "scheduled"


async def test_enrichment_never_runs_for_a_refused_call(tmp_path, monkeypatch):
    """Enrichment is downstream of enforcement: a disabled tool and a
    hard-blocked tool both refuse without touching the writer."""
    server, _, writer = await _probe(tmp_path, monkeypatch, listing=[_entry()],
                                     disabled=True)

    with pytest.raises(ToolError, match="disabled by the administrator"):
        await _call(server)
    with pytest.raises(ToolError, match="remote gateway mode"):
        await server.call_tool("upload_media", {"file_path": "/etc/passwd"})
    assert writer.calls == 0
