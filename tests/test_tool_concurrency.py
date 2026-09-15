"""Controlled concurrency for identical tool calls (feature 2).

A client firing the SAME tool many times in parallel is the pattern X
rate-limits and flags as automation. The middleware therefore:

* caps in-flight identical calls per (caller, tool) pair and refuses the
  overflow outright — it is never queued;
* spaces identical follow-ups that overlap by
  ``TOOL_MIN_GAP_SECONDS + uniform(0, TOOL_GAP_JITTER_SECONDS)``;
* drops every counter when nothing is in flight.

Deterministic by construction: the injected ``sleep`` records the delay
instead of waiting, jitter is a fixed value, and the ``probe`` tool blocks on
an ``asyncio.Event`` the test controls — no real traffic, no real waits.
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest
from fastapi.testclient import TestClient
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from app import context, tool_middleware
from app.config import Settings
from app.db import AccountStore
from app.db_resilience import DB_ERROR_KINDS
from app.models import GatewayState

MCP = {"Authorization": f"Bearer {os.environ['MCP_ACCESS_TOKEN']}"}


class _Delays:
    """The injected sleep: records each delay instead of waiting on it."""

    def __init__(self):
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


class _Harness:
    """A FastMCP server with the gateway middleware attached.

    ``probe`` blocks on ``gate`` once it is executing, so a call can be held
    in flight while the test starts more calls; ``other`` returns at once.
    """

    def __init__(self, server, store, middleware, gate, delays, started):
        self.server = server
        self.store = store
        self.middleware = middleware
        self.gate = gate
        self.delays = delays
        self.started = started

    def call(self, tool: str, text: str = "x", caller: str = "caller-a"):
        """Start one call as a task (the caller fingerprint is set inside it)."""

        async def go():
            context.caller_fp.set(caller)
            return await self.server.call_tool(tool, {"text": text})

        return asyncio.create_task(go())

    async def wait_started(self, count: int, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while len(self.started) < count:
            assert time.monotonic() < deadline, f"only {len(self.started)} calls started"
            await asyncio.sleep(0.005)


async def _harness(tmp_path, *, cap=2, min_gap=1.5, jitter=3.0, rand_value=1.0,
                   db="pacing.db"):
    """Build the server + middleware. Nothing here ever sleeps for real."""
    server = FastMCP("pacing-probe")
    gate = asyncio.Event()
    started: list[str] = []

    @server.tool
    async def probe(text: str = "x") -> str:
        started.append(text)
        await gate.wait()
        return f"ran:{text}"

    @server.tool
    async def other(text: str = "x") -> str:
        started.append(text)
        return f"other:{text}"

    store = AccountStore(f"sqlite:///{tmp_path / db}")
    await store.connect()
    await store.init_schema()
    state = GatewayState()
    state.tool_names = ["probe", "other"]
    settings = Settings(TOOL_MAX_CONCURRENT_IDENTICAL=cap,
                        TOOL_MIN_GAP_SECONDS=min_gap,
                        TOOL_GAP_JITTER_SECONDS=jitter)
    delays = _Delays()
    middleware = tool_middleware.UsageAndFlagsMiddleware(
        store, state, settings=settings, sleep=delays, rand=lambda: rand_value)
    server.add_middleware(middleware)
    return _Harness(server, store, middleware, gate, delays, started)


# ── the cap ──────────────────────────────────────────────────────────────

async def test_two_identical_calls_allowed_the_third_is_refused(tmp_path):
    h = await _harness(tmp_path, cap=2)
    first, second = h.call("probe", "a"), h.call("probe", "b")
    await h.wait_started(2)

    with pytest.raises(ToolError) as caught:
        await h.call("probe", "c")
    message = str(caught.value)
    assert "Too many concurrent calls to 'probe'" in message
    assert "retry_after=" in message, "a caller must be told what to wait"
    assert "2" in message and "in flight" in message
    assert len(h.started) == 2, "the refused call must not reach the tool"

    h.gate.set()
    results = await asyncio.gather(first, second)
    assert {r.content[0].text for r in results} == {"ran:a", "ran:b"}


async def test_overflow_is_recorded_in_usage_and_never_queued(tmp_path):
    h = await _harness(tmp_path, cap=1)
    first = h.call("probe", "a")
    await h.wait_started(1)
    sleeps_before = len(h.delays.delays)

    with pytest.raises(ToolError):
        await h.call("probe", "b")

    assert len(h.delays.delays) == sleeps_before, "a refused call must not wait"
    rows = await h.store.list_tool_usage(limit=10)
    rejection = [r for r in rows if r["ok"] is False]
    assert rejection, "the refusal must be visible in usage logging"
    assert "concurrency cap" in (rejection[0]["error"] or "")
    assert "retry_after" in (rejection[0]["error"] or "")

    h.gate.set()
    await first


async def test_different_tools_are_not_blocked_by_the_cap(tmp_path):
    h = await _harness(tmp_path, cap=1)
    held = h.call("probe", "a")
    await h.wait_started(1)

    # Same caller, a different tool: its own pair, its own (empty) budget.
    result = await h.call("other", "z")
    assert "other:z" in result.content[0].text
    assert h.delays.delays[-1] == 0.0, "a different tool never waits on this pair"

    h.gate.set()
    await held


async def test_different_callers_are_not_blocked_by_the_cap(tmp_path):
    h = await _harness(tmp_path, cap=1)
    held = h.call("probe", "a", caller="caller-a")
    await h.wait_started(1)

    # A second caller's identical call is a different key, so it is admitted
    # immediately rather than refused by the cap. It still blocks inside the
    # tool until the gate opens, so start it, prove it was admitted, and only
    # then release the gate and collect both results.
    second = h.call("probe", "b", caller="caller-b")
    await h.wait_started(2)
    assert h.delays.delays[-1] == 0.0

    h.gate.set()
    await held
    result = await second
    assert "ran:b" in result.content[0].text


async def test_slots_are_released_on_completion_and_the_entry_is_dropped(tmp_path):
    h = await _harness(tmp_path, cap=2)
    tasks = [h.call("probe", "a"), h.call("probe", "b")]
    await h.wait_started(2)
    assert h.middleware.concurrency_snapshot()["in_flight_total"] == 2
    assert h.middleware.concurrency_snapshot()["in_flight_pairs"] == 1

    h.gate.set()
    await asyncio.gather(*tasks)

    snapshot = h.middleware.concurrency_snapshot()
    assert snapshot["in_flight_total"] == 0
    assert snapshot["in_flight_pairs"] == 0, "counters must not leak"
    assert h.middleware._pairs == {}, "the pair entry is dropped when idle"

    # And the slot really is free: a fresh call is admitted.
    again = h.call("probe", "c")
    await h.wait_started(3)
    h.gate.set()
    await again


async def test_slots_are_released_when_the_tool_raises(tmp_path):
    server = FastMCP("raise-probe")

    @server.tool
    async def boom(text: str = "x") -> str:
        raise RuntimeError("upstream exploded")

    store = AccountStore(f"sqlite:///{tmp_path / 'raise.db'}")
    await store.connect()
    await store.init_schema()
    state = GatewayState()
    state.tool_names = ["boom"]
    middleware = tool_middleware.UsageAndFlagsMiddleware(
        store, state, settings=Settings(), sleep=_Delays(), rand=lambda: 0.0)
    server.add_middleware(middleware)

    with pytest.raises(Exception):
        await server.call_tool("boom", {"text": "x"})

    assert middleware.concurrency_snapshot()["in_flight_total"] == 0
    assert middleware._pairs == {}, "an exception must release the slot too"
    rows = await store.list_tool_usage(limit=5)
    assert rows and rows[0]["ok"] is False and "RuntimeError" in rows[0]["error"]


async def test_counters_do_not_accumulate_across_many_pairs(tmp_path):
    h = await _harness(tmp_path, cap=2)
    for index in range(25):
        await h.call("other", f"t{index}", caller=f"caller-{index}")
    assert h.middleware._pairs == {}
    assert h.middleware.concurrency_snapshot()["in_flight_pairs"] == 0


async def test_cap_zero_is_clamped_to_one(tmp_path):
    """A nonsensical cap must not become "refuse everything"."""
    h = await _harness(tmp_path, cap=0, min_gap=0.0, jitter=0.0)
    assert h.middleware.max_concurrent_identical == 1
    result = await h.call("other", "z")
    assert "other:z" in result.content[0].text


async def test_policy_refusals_do_not_take_a_slot(tmp_path):
    """Hard-blocked/disabled calls never reach the pacing layer."""
    store = AccountStore(f"sqlite:///{tmp_path / 'blocked.db'}")
    await store.connect()
    await store.init_schema()
    await store.set_tool_flag("get_user", False)
    state = GatewayState()
    state.tool_names = ["get_user"]
    middleware = tool_middleware.UsageAndFlagsMiddleware(
        store, state, settings=Settings(TOOL_MAX_CONCURRENT_IDENTICAL=1),
        sleep=_Delays(), rand=lambda: 0.0)
    server = FastMCP("policy-probe")
    server.add_middleware(middleware)

    with pytest.raises(ToolError):
        await server.call_tool("get_user", {"username": "nasa"})   # disabled
    with pytest.raises(ToolError):
        await server.call_tool("upload_media", {"file_path": "/etc/passwd"})

    assert middleware._pairs == {}, "a refused call must not occupy a pair slot"
    assert middleware.concurrency_snapshot()["rejected_total"] == 0


# ── the jittered gap ─────────────────────────────────────────────────────

@pytest.mark.parametrize("rand_value", [0.0, 0.25, 0.5, 1.0])
async def test_gap_is_within_min_and_min_plus_jitter_for_a_follow_up(tmp_path, rand_value):
    h = await _harness(tmp_path, min_gap=1.5, jitter=3.0, rand_value=rand_value)
    first = h.call("probe", "a")
    await h.wait_started(1)
    second = h.call("probe", "b")
    await h.wait_started(2)
    await h.call("other", "c")

    delays = h.delays.delays
    assert delays[0] == 0.0, "the first call of a burst is never delayed"
    assert 1.5 <= delays[1] <= 1.5 + 3.0, delays
    assert delays[1] == pytest.approx(1.5 + rand_value * 3.0)
    assert delays[2] == 0.0, "a different tool never waits"

    h.gate.set()
    await asyncio.gather(first, second)


async def test_gap_is_skipped_entirely_when_configured_off(tmp_path):
    h = await _harness(tmp_path, min_gap=0.0, jitter=0.0)
    first = h.call("probe", "a")
    await h.wait_started(1)
    second = h.call("probe", "b")
    await h.wait_started(2)
    assert h.delays.delays == [0.0, 0.0]

    h.gate.set()
    await asyncio.gather(first, second)


async def test_wait_does_not_hold_a_lock_that_blocks_other_pairs(tmp_path):
    """A pair parked in its gap must not stall unrelated calls: the delay is
    computed under the lock, the sleeping happens outside it."""
    delays = _Delays()
    released = asyncio.Event()

    async def blocking_sleep(delay: float):
        delays.delays.append(delay)
        if delay > 0:                       # the paced follow-up parks here
            await released.wait()

    server = FastMCP("lock-probe")
    gate = asyncio.Event()
    started: list[str] = []

    @server.tool
    async def probe(text: str = "x") -> str:
        started.append(text)
        await gate.wait()
        return f"ran:{text}"

    @server.tool
    async def other(text: str = "x") -> str:
        started.append(text)
        return f"other:{text}"

    store = AccountStore(f"sqlite:///{tmp_path / 'lock.db'}")
    await store.connect()
    await store.init_schema()
    state = GatewayState()
    state.tool_names = ["probe", "other"]
    middleware = tool_middleware.UsageAndFlagsMiddleware(
        store, state,
        settings=Settings(TOOL_MIN_GAP_SECONDS=1.5, TOOL_GAP_JITTER_SECONDS=3.0),
        sleep=blocking_sleep, rand=lambda: 0.0)
    server.add_middleware(middleware)

    def call(tool, text):
        async def go():
            context.caller_fp.set("caller-a")
            return await server.call_tool(tool, {"text": text})
        return asyncio.create_task(go())

    first = call("probe", "a")
    while not started:
        await asyncio.sleep(0.005)
    follow_up = call("probe", "b")                     # waits in the gap
    while len(delays.delays) < 2:
        await asyncio.sleep(0.005)

    # The follow-up is parked inside its sleep AND holding its slot, yet an
    # unrelated call completes right away — no lock is held while waiting.
    other = await asyncio.wait_for(call("other", "z"), timeout=2.0)
    assert "other:z" in other.content[0].text

    released.set()
    gate.set()
    await asyncio.wait_for(first, timeout=2.0)
    await asyncio.wait_for(follow_up, timeout=2.0)
    assert started == ["a", "z", "b"]


# ── observability ────────────────────────────────────────────────────────

def test_concurrency_status_without_the_middleware():
    settings = Settings(TOOL_MAX_CONCURRENT_IDENTICAL=2,
                        TOOL_MIN_GAP_SECONDS=1.5, TOOL_GAP_JITTER_SECONDS=3.0)
    status = tool_middleware.concurrency_status(None, settings)
    assert status["max_concurrent_identical"] == 2
    assert status["min_gap_seconds"] == 1.5
    assert status["gap_jitter_seconds"] == 3.0
    assert status["in_flight_total"] == 0 and status["rejected_total"] == 0


def test_diagnostics_exposes_the_concurrency_limits(client):
    r = client.get("/diagnostics", headers=MCP)
    assert r.status_code == 200
    concurrency = r.json()["tool_concurrency"]
    assert concurrency["max_concurrent_identical"] == 2, "the documented default"
    assert concurrency["min_gap_seconds"] == 1.5
    assert concurrency["gap_jitter_seconds"] == 3.0
    assert isinstance(concurrency["in_flight_total"], int)
    assert isinstance(concurrency["rejected_total"], int)


def test_diagnostics_exposes_the_database_policy_without_the_dsn(client):
    body = client.get("/diagnostics", headers=MCP).json()
    database = body["database"]
    assert database["ok"] is True
    assert set(database) == {"backend", "ok", "error_kind", "hint",
                             "max_attempts", "base_delay_seconds",
                             "max_delay_seconds"}
    assert database["error_kind"] is None and database["hint"] is None
    assert database["max_attempts"] == 5

    text = client.get("/diagnostics", headers=MCP).text
    dsn = os.environ["DATABASE_URL"]
    assert dsn not in text, "the DSN must never be echoed"
    assert dsn.removeprefix("sqlite:///") not in text, "nor its filesystem path"
    assert os.environ["MCP_ACCESS_TOKEN"] not in text
    assert os.environ["ADMIN_TOKEN"] not in text


# ── degraded start (feature 1, end to end) ───────────────────────────────

def test_gateway_starts_and_reports_a_classified_failure_when_the_store_is_broken(tmp_path):
    """A store that cannot connect must not stop the gateway: startup
    completes, /status says so, /diagnostics explains why. The backoff is
    configured to zero delay, so this test never waits either."""
    from app.main import create_app

    # A sqlite DSN whose parent path is an ordinary file: connect() fails
    # deterministically, with no network and no driver involved.
    blocker = tmp_path / "blocker.txt"
    blocker.write_text("not a directory", encoding="utf-8")
    settings = Settings(
        MCP_ACCESS_TOKEN="m" * 48,
        ADMIN_TOKEN="a" * 48,
        DATABASE_URL=f"sqlite:///{blocker / 'x.db'}",
        SPECTRE_DB_PATH=str(tmp_path / "spectre.db"),
        DB_CONNECT_MAX_ATTEMPTS=2,
        DB_CONNECT_BASE_DELAY_SECONDS=0.0,
        DB_CONNECT_MAX_DELAY_SECONDS=0.0,
        VALIDATE_ON_STARTUP=False,
        SESSION_CHECK_INTERVAL_SECONDS=3600,
        LOG_LEVEL="WARNING",
    )
    app = create_app(settings)
    mcp = {"Authorization": f"Bearer {'m' * 48}"}

    with TestClient(app) as client:
        assert client.get("/health").status_code == 200, "the gateway still serves"
        assert client.get("/status").json()["db_ok"] is False
        response = client.get("/diagnostics", headers=mcp)
        assert response.status_code == 200
        database = response.json()["database"]
        assert database["ok"] is False
        assert database["error_kind"] in DB_ERROR_KINDS
        assert database["hint"], "a degraded start must say what to check"
        assert str(blocker) not in response.text, "no filesystem path leaks"
        assert client.get("/tools", headers=mcp).status_code == 200
