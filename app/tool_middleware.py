"""FastMCP middleware layered onto spectre's live server object.

Hooks every tools/call to:
1. enforce the admin-controlled enable/disable flag per tool,
2. pace identical calls from one caller (concurrency cap + jittered gap),
3. record usage (tool, ok/error, duration, caller fingerprint) in the DB,
4. best-effort result enrichment for the few write tools whose upstream
   result is not actionable on its own (see TOOL_ENRICHERS below).

No spectre source is modified; the middleware is added once at startup via
mcp.add_middleware() (guarded against double-registration).
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from datetime import datetime, timezone
from typing import Awaitable, Callable

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from . import context
from .config import get_settings
from .logging_setup import get_logger, sanitize_error


def _root_cause(exc: BaseException) -> BaseException:
    """Follow ``__cause__`` to the original failure.

    Tool frameworks commonly re-raise a tool's exception wrapped in their own
    type (FastMCP raises ``ToolError`` "Error calling tool ..."), which would
    otherwise hide the real cause in the usage log and the admin dashboard.
    Only an explicit ``__cause__`` chain is followed - ``__context__`` can
    carry an unrelated incidental exception.
    """
    seen: set[int] = set()
    root = exc
    while True:
        nxt = root.__cause__
        if nxt is None or id(nxt) in seen:
            return root
        seen.add(id(nxt))
        root = nxt


def _error_summary(exc: BaseException) -> str:
    """Recorded error text: the direct failure plus its root cause if wrapped."""
    direct = f"{type(exc).__name__}: {exc}"
    root = _root_cause(exc)
    if root is exc:
        return direct
    return f"{direct} | caused by {type(root).__name__}: {root}"


log = get_logger("kxstrel-x-mcp.tools")

_FLAG_TTL_SECONDS = 15

# Injection seams: tests replace these (or pass sleep=/rand= to the
# middleware) so no test ever waits on a real clock.
_SLEEP = asyncio.sleep
_RAND = random.random

# Caller fingerprint of a call that arrived without one (the admin tool
# tester runs in-process). Pacing still applies to it, so a dashboard script
# cannot be used as an unpaced bypass.
_ANONYMOUS_CALLER = "anonymous"

# What a refused caller is told to wait, when pacing is configured. With
# pacing disabled the hint falls back to "a moment" rather than 0.
_BUSY_RETRY_AFTER_FLOOR_SECONDS = 1.0

# Hard-blocked in remote-gateway mode, regardless of admin flags:
# - the media/profile-image tools take a server-local file_path and stream
#   its bytes to X's public upload CDN — an arbitrary-file-read exfiltration
#   chain (read .env / DB / pool file, then post the media publicly);
# - remove_account lets any MCP client drop configured accounts from the
#   pool (use the admin dashboard's account management instead).
BLOCKED_TOOLS = frozenset({
    "upload_media", "update_profile_image", "update_profile_banner",
    "remove_account",
})

BLOCKED_REASON = (
    "blocked in remote gateway mode: local file access / pool mutation is "
    "not exposed to MCP clients"
)

# Argument keys that request server-local file access. Spectre's media tools
# take `file_path`; the check is recursive so a nested payload cannot slip a
# local path past the top-level scan.
_FILE_PATH_KEYS = frozenset({"file_path"})


def contains_file_path(arguments: object, _depth: int = 0) -> bool:
    """True when the argument tree carries a server-local file path key."""
    if _depth > 8:
        return False  # pathological nesting: depth cap, nothing runs anyway
    if isinstance(arguments, dict):
        for key, value in arguments.items():
            if isinstance(key, str) and key.strip().lower() in _FILE_PATH_KEYS:
                return True
            if contains_file_path(value, _depth + 1):
                return True
        return False
    if isinstance(arguments, (list, tuple)):
        return any(contains_file_path(item, _depth + 1) for item in arguments)
    return False


# ── result enrichment ────────────────────────────────────────────────────
#
# Some upstream write tools report success but hand the caller nothing to act
# on. Spectre 1.0.3's `schedule_tweet` discards the CreateScheduledTweet
# response, so the id of the tweet it just created never reaches the caller —
# and `edit_scheduled_tweet` / `delete_scheduled_tweet` (which require
# `scheduled_id` / `tweet_id`) cannot be driven from its result. The id *is*
# recoverable from the tool's own listing (`get_scheduled_tweets`), so the
# gateway appends it, clearly marked as gateway-recovered.
#
# Rules every enricher in TOOL_ENRICHERS must follow:
# - best effort only: never raise, never remove or rewrite an upstream field,
#   and any failure (import, upstream error, unexpected shape, parse failure,
#   timeout) leaves the ORIGINAL result byte-for-byte untouched;
# - never guess: a recovered id is added only when exactly ONE listing entry
#   matches on both the tweet text and the execution time;
# - mark provenance in-band, so the added field can never be mistaken for a
#   native upstream field if it is read without this file open.

_ENRICH_TIMEOUT_SECONDS = 8.0

# `schedule_tweet` reports the execution time in SECONDS
# (`execute_at_timestamp`) while `get_scheduled_tweets` lists it in
# MILLISECONDS (`execute_at`): the conversion is the whole point of
# _expected_execute_at_ms. This tolerance absorbs sub-second rounding only —
# anything further apart is a different entry, and an ambiguous match is not
# used at all.
_EXECUTE_AT_TOLERANCE_MS = 1_000

# Provenance note travels with the value, so a client that prints the JSON
# (dashboard tester, raw MCP client) states where the id came from. Chosen as
# a sibling `scheduled_id_note` rather than a wrapper object: the id stays a
# plain top-level field for `delete_scheduled_tweet`-style argument plumbing,
# and no upstream field is renamed or nested.
_SCHEDULED_ID_NOTE = (
    "recovered by the gateway from get_scheduled_tweets; "
    "not returned by the create call"
)

# Container keys a listing response may wrap its entries in.
_LIST_KEYS = (
    "scheduled_tweets", "scheduled", "tweets", "data", "items", "results",
    "entries", "result",
)


def _block_text(block: object) -> str | None:
    """The text of a content block (mcp ContentBlock or a plain dict)."""
    text = block.get("text") if isinstance(block, dict) else getattr(block, "text", None)
    return text if isinstance(text, str) else None


def _load_json_object(text: object) -> dict | None:
    """Parse `text` as a JSON *object*; anything else yields None."""
    if not isinstance(text, str) or text.lstrip()[:1] != "{":
        return None
    try:
        parsed = json.loads(text)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _as_text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _as_int(value: object) -> int | None:
    """Epoch values show up as int, float and (sometimes) digit strings."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped[:1] in "-+" and stripped[1:].isdigit():
            return int(stripped)
        if stripped.isdigit():
            return int(stripped)
    return None


def _parse_iso_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except Exception:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _result_payload(result: object) -> dict | None:
    """The JSON object a tool returned, as far as one can be identified.

    Spectre tools are declared `-> str`, so the payload normally arrives as
    JSON text in the first text block; fastmcp additionally wraps it as
    `structured_content = {"result": "<that same string>"}`. Both are read so
    either representation alone is enough to enrich."""
    for block in getattr(result, "content", None) or []:
        payload = _load_json_object(_block_text(block))
        if payload is not None:
            return payload
    envelope = getattr(result, "structured_content", None)
    if isinstance(envelope, dict):
        inner = envelope.get("result")
        if isinstance(inner, str):
            return _load_json_object(inner)
        if "status" in envelope or "error" in envelope:
            return envelope
    return None


def _assign_field(holder: object, key: str | None, value: object) -> None:
    if key is None:  # the holder itself is the payload mapping
        holder.clear()  # type: ignore[union-attr]
        holder.update(value)  # type: ignore[union-attr]
    elif isinstance(holder, dict):
        holder[key] = value
    else:
        setattr(holder, key, value)


def _rewrite_payload(result: object, payload: dict) -> bool:
    """Replace the returned JSON object in place, in every representation
    that carried it, so the text view and styled content cannot disagree.

    All-or-nothing: if any representation refuses the write, the ones already
    written are restored and the caller keeps its original result."""
    rendered = json.dumps(payload)
    edits: list[tuple[object, str | None, object]] = []
    envelope = getattr(result, "structured_content", None)
    if isinstance(envelope, dict):
        inner = envelope.get("result")
        if isinstance(inner, str) and _load_json_object(inner) is not None:
            edits.append((envelope, "result", inner))
        elif "status" in envelope or "error" in envelope:
            edits.append((envelope, None, dict(envelope)))
    for block in getattr(result, "content", None) or []:
        text = _block_text(block)
        if _load_json_object(text) is not None:
            edits.append((block, "text", text))
    if not edits:
        return False
    try:
        for index, (holder, key, _original) in enumerate(edits):
            _assign_field(holder, key, rendered if key is not None else payload)
    except Exception:
        for holder, key, original in edits[:index]:
            try:
                _assign_field(holder, key, original)
            except Exception:  # pragma: no cover - defensive restore
                pass
        raise
    return True


def _scheduled_entries(payload: object, _depth: int = 0) -> list[dict] | None:
    """The entry list out of a get_scheduled_tweets response, or None when the
    shape is not recognised (unrecognised shapes are never guessed at)."""
    if _depth > 3:
        return None
    if isinstance(payload, str):
        try:
            return _scheduled_entries(json.loads(payload), _depth + 1)
        except Exception:
            return None
    if isinstance(payload, list):
        entries = [item for item in payload if isinstance(item, dict)]
        return entries or None
    if isinstance(payload, dict):
        if "scheduled_id" in payload:
            return [payload]
        for key in _LIST_KEYS:
            if key in payload:
                found = _scheduled_entries(payload[key], _depth + 1)
                if found:
                    return found
    return None


def _expected_execute_at_ms(payload: dict, arguments: dict) -> int | None:
    """The created tweet's execution time in MILLISECONDS.

    `schedule_tweet` reports `execute_at_timestamp` in seconds; the listing
    reports `execute_at` in milliseconds. The `* 1000` is what makes the two
    comparable at all."""
    seconds = _as_int(payload.get("execute_at_timestamp"))
    if seconds is None:
        seconds = _as_int(arguments.get("execute_at_timestamp"))
    if seconds is not None:
        return seconds * 1000
    parsed = (_parse_iso_utc(arguments.get("execute_at"))
              or _parse_iso_utc(payload.get("execute_at")))
    return int(parsed.timestamp() * 1000) if parsed else None


def _entry_matches(entry: dict, text: str, expected_ms: int) -> bool:
    entry_ms = _as_int(entry.get("execute_at"))
    if entry_ms is None or abs(entry_ms - expected_ms) > _EXECUTE_AT_TOLERANCE_MS:
        return False
    entry_text = _as_text(entry.get("text"))
    return bool(entry_text) and entry_text.strip() == text.strip()


def _get_writer() -> object:
    """Spectre's own writer accessor — the same wiring the tools themselves
    use, so the gateway never builds a second X client. Imported lazily: a
    missing or broken spectre install must degrade to "no enrichment", never
    break startup.

    The writer serves whichever account it would use for the tool call
    itself; a pool that rotates accounts per request can therefore list a
    different account's scheduled tweets, which simply matches nothing and
    leaves the result alone."""
    from spectre.server import _get_writer as spectre_get_writer

    return spectre_get_writer()


async def _fetch_scheduled_entries() -> list[dict] | None:
    """Read the caller's scheduled-tweet listing through the writer."""
    writer = _get_writer()
    listing = await asyncio.wait_for(
        writer.get_scheduled_tweets(), _ENRICH_TIMEOUT_SECONDS)
    return _scheduled_entries(listing)


async def _enrich_schedule_tweet(arguments: dict, result: object) -> None:
    """Append the created scheduled tweet's id to a successful
    `schedule_tweet` result (see the section comment for the rules)."""
    payload = _result_payload(result)
    if payload is None or payload.get("error") or payload.get("status") != "scheduled":
        return  # nothing was created, or the shape is not the one we know
    text = _as_text(payload.get("text")) or _as_text(arguments.get("text"))
    expected_ms = _expected_execute_at_ms(payload, arguments)
    if not text or expected_ms is None:
        return  # nothing trustworthy to match on — do not guess
    entries = await _fetch_scheduled_entries() or []
    candidates = [entry for entry in entries
                  if _entry_matches(entry, text, expected_ms)]
    if len(candidates) != 1:
        log.info("schedule_tweet enrichment skipped: %d listing matches",
                 len(candidates))
        return
    scheduled_id = _as_text(candidates[0].get("scheduled_id"))
    if not scheduled_id:
        log.info("schedule_tweet enrichment skipped: listing entry carries no scheduled_id")
        return
    enriched = dict(payload)
    enriched["scheduled_id"] = scheduled_id
    enriched["scheduled_id_note"] = _SCHEDULED_ID_NOTE
    _rewrite_payload(result, enriched)
    log.info("schedule_tweet enriched with gateway-recovered scheduled_id=%s",
             scheduled_id)


# tool name -> enricher. Explicit and extensible: a new upstream gap gets one
# entry here plus one test file, nothing else changes.
TOOL_ENRICHERS: dict[str, Callable[[dict, object], Awaitable[None]]] = {
    "schedule_tweet": _enrich_schedule_tweet,
}


async def enrich_result(tool_name: str, arguments: object, result: object) -> object:
    """Apply the enricher registered for `tool_name`, if any.

    Best effort by construction: the enricher mutates the result in place and
    this function always returns the caller's result object. A failure is
    logged (redacted) and the call still succeeds — enrichment can never turn
    a working tool call into a failed one."""
    enricher = TOOL_ENRICHERS.get(tool_name)
    if enricher is None or result is None or getattr(result, "is_error", False):
        return result
    try:
        await enricher(arguments if isinstance(arguments, dict) else {}, result)
    except Exception as exc:
        log.warning("result enrichment failed tool=%s: %s", tool_name,
                    sanitize_error(_error_summary(exc)))
    return result


class _PairState:
    """Live state for one (caller, tool) pair.

    One entry per pair that has calls in flight; the entry is deleted the
    moment the last call finishes (see ``_release``), so a long-running
    process cannot accumulate keys no matter how many callers or tool names
    it sees.
    """

    __slots__ = ("in_flight",)

    def __init__(self) -> None:
        self.in_flight = 0


class UsageAndFlagsMiddleware(Middleware):
    def __init__(self, store, state, *, settings=None, sleep=None, rand=None):
        self.store = store
        self.state = state
        self._flags: dict[str, bool] = {}
        self._flags_loaded_at = 0.0
        self._flag_lock = None
        self._flags_loaded = False
        # -- identical-call pacing (per caller + tool) --------------------
        settings = settings or get_settings()
        # A cap of 0 would refuse every call, which is never the intent:
        # the floor is 1 (the setting exists to bound, not to disable).
        self.max_concurrent_identical = max(
            1, int(settings.TOOL_MAX_CONCURRENT_IDENTICAL))
        self.min_gap_seconds = max(0.0, float(settings.TOOL_MIN_GAP_SECONDS))
        self.gap_jitter_seconds = max(0.0, float(settings.TOOL_GAP_JITTER_SECONDS))
        self._pairs: dict[tuple[str, str], _PairState] = {}
        self._pacing_lock = None
        self._rejected_total = 0
        self._sleep = sleep   # None => module seam _SLEEP (patchable)
        self._rand = rand

    # -- identical-call pacing -------------------------------------------
    def _pacing_lock_or_create(self) -> asyncio.Lock:
        # Created lazily: an asyncio.Lock built at import time would bind to
        # no particular loop, and this middleware may be constructed outside
        # a running loop (app factory).
        if self._pacing_lock is None:
            self._pacing_lock = asyncio.Lock()
        return self._pacing_lock

    def _pair_key(self, tool_name: str) -> tuple[str, str]:
        return (context.caller_fp.get() or _ANONYMOUS_CALLER, tool_name)

    async def _admit(self, tool_name: str) -> tuple[tuple[str, str], float] | None:
        """Reserve an in-flight slot for this (caller, tool) pair.

        Returns ``(key, delay_seconds)``: the delay is 0.0 for the first call
        of a burst and ``min_gap + uniform(0, jitter)`` for an identical
        follow-up that overlaps it (jitter is deliberate — a perfectly
        regular cadence is itself a signature). Returns None when the pair is
        already at its cap: the caller is refused, never queued, so a burst
        cannot grow an unbounded backlog of waiters.
        """
        key = self._pair_key(tool_name)
        async with self._pacing_lock_or_create():
            pair = self._pairs.get(key)
            if pair is not None and pair.in_flight >= self.max_concurrent_identical:
                return None
            if pair is None:
                pair = self._pairs[key] = _PairState()
                delay = 0.0
            else:
                rand = self._rand if self._rand is not None else _RAND
                delay = self.min_gap_seconds + rand() * self.gap_jitter_seconds
            pair.in_flight += 1
        return key, delay

    async def _release(self, key: tuple[str, str]) -> None:
        """Give the slot back — on success AND on exception."""
        async with self._pacing_lock_or_create():
            pair = self._pairs.get(key)
            if pair is None:  # pragma: no cover - defensive: never admitted twice
                return
            pair.in_flight -= 1
            if pair.in_flight <= 0:
                del self._pairs[key]  # nothing in flight: drop the key entirely

    async def _wait_for_gap(self, delay: float) -> None:
        """Sleep outside every lock (never hold one while waiting)."""
        sleep = self._sleep if self._sleep is not None else _SLEEP
        await sleep(delay)

    def busy_retry_after_seconds(self) -> float:
        """The wait a refused caller is told to observe."""
        return max(_BUSY_RETRY_AFTER_FLOOR_SECONDS,
                   self.min_gap_seconds + self.gap_jitter_seconds)

    def busy_message(self, tool_name: str) -> str:
        """Refusal text: what happened, and what the caller can do about it."""
        retry_after = self.busy_retry_after_seconds()
        return (
            f"Too many concurrent calls to '{tool_name}': this caller already has "
            f"{self.max_concurrent_identical} identical call(s) in flight "
            f"(TOOL_MAX_CONCURRENT_IDENTICAL). retry_after={retry_after:.1f}s — "
            "identical calls are paced so the upstream does not see an "
            "automation-like burst; wait and retry, or call a different tool."
        )

    def concurrency_snapshot(self) -> dict:
        """Live counters for the diagnostics surface."""
        pairs = list(self._pairs.values())
        return {
            "in_flight_pairs": len(pairs),
            "in_flight_total": sum(p.in_flight for p in pairs),
            "rejected_total": self._rejected_total,
        }

    async def _refresh_flags(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._flags_loaded_at < _FLAG_TTL_SECONDS:
            return
        if self._flag_lock is None:
            self._flag_lock = asyncio.Lock()
        async with self._flag_lock:
            if not force and time.monotonic() - self._flags_loaded_at < _FLAG_TTL_SECONDS:
                return
            try:
                self._flags = await self.store.list_tool_flags()
                self._flags_loaded_at = time.monotonic()
                self._flags_loaded = True
            except Exception as exc:
                log.warning("tool flags refresh failed: %s", sanitize_error(str(exc)))
                self._flags_loaded_at = time.monotonic()  # retry after TTL, don't hammer

    async def refresh_flags(self) -> None:
        await self._refresh_flags(force=True)

    async def on_call_tool(self, context: MiddlewareContext, call_next: CallNext):
        params = context.message
        tool_name = params.name
        # Hard security boundary (independent of admin toggles).
        if tool_name in BLOCKED_TOOLS:
            log.info("blocked hard-disabled tool=%s", tool_name)
            await self._record(tool_name, False, "blocked: remote-gateway mode", 0.0)
            raise ToolError(f"Tool '{tool_name}' is {BLOCKED_REASON}.")
        arguments = getattr(params, "arguments", None) or {}
        if contains_file_path(arguments):
            log.info("blocked tool=%s with file_path argument", tool_name)
            await self._record(tool_name, False, "blocked: file_path argument", 0.0)
            raise ToolError(
                "Tools taking a server-local file_path are disabled in remote "
                "gateway mode; no local file access is exposed to MCP clients.")
        await self._refresh_flags()
        if not self._flags_loaded:
            await self._record(tool_name, False, "policy unavailable", 0.0)
            raise ToolError("Tool policy is temporarily unavailable; try again later.")
        if self._flags.get(tool_name) is False:
            log.info("blocked disabled tool=%s", tool_name)
            await self._record(tool_name, False, "disabled by administrator", 0.0)
            raise ToolError(f"Tool '{tool_name}' is disabled by the administrator.")
        # Pacing is downstream of policy: a refused call must not occupy a
        # slot or create a gap for the pair.
        admission = await self._admit(tool_name)
        if admission is None:
            self._rejected_total += 1
            log.info("refused identical-concurrency overflow tool=%s cap=%d",
                     tool_name, self.max_concurrent_identical)
            await self._record(
                tool_name, False,
                f"concurrency cap: {self.max_concurrent_identical} identical calls"
                f" in flight, retry_after={self.busy_retry_after_seconds():.1f}s",
                0.0)
            raise ToolError(self.busy_message(tool_name))
        key, delay = admission
        started = 0.0
        try:
            # Space identical follow-ups. Different tools and other callers
            # have their own keys and never wait on this one.
            await self._wait_for_gap(delay)
            started = time.monotonic()
            result = await call_next(context)
        except Exception as exc:
            await self._record(tool_name, False, _error_summary(exc),
                               (time.monotonic() - started) * 1000 if started else 0.0)
            raise
        finally:
            await self._release(key)
        # Best-effort only, and never for a failed call. Any extra upstream
        # latency it costs is part of what the caller waited for, so it is
        # recorded inside the same duration.
        result = await enrich_result(tool_name, arguments, result)
        await self._record(tool_name, True, None, (time.monotonic() - started) * 1000)
        return result

    async def _record(self, tool_name: str, ok: bool, error: str | None, duration_ms: float) -> None:
        from . import metrics_setup

        # Only known tool names become Prometheus labels. Unknown wire values
        # are grouped so an authenticated caller cannot create unbounded
        # metric series.
        metric_tool = tool_name[:64] if tool_name in self.state.tool_names else "unknown"
        metrics_setup.tool_calls_total.labels(tool=metric_tool, ok="1" if ok else "0").inc()
        metrics_setup.tool_duration_ms.observe(duration_ms)
        try:
            await self.store.log_tool_usage(
                tool_name, ok, error, int(duration_ms), context.caller_fp.get()
            )
        except Exception as exc:  # never break a tool call because of logging
            log.warning("usage log write failed: %s", sanitize_error(str(exc)))


def concurrency_status(middleware, settings) -> dict:
    """The configured identical-call limits plus live counters.

    Always reports the configured values, even when the middleware is not
    attached (a store-less gateway still answers /diagnostics), so a caller
    hitting the cap and an operator reading the dashboard see the same
    numbers.
    """
    status = {
        "max_concurrent_identical": int(settings.TOOL_MAX_CONCURRENT_IDENTICAL),
        "min_gap_seconds": float(settings.TOOL_MIN_GAP_SECONDS),
        "gap_jitter_seconds": float(settings.TOOL_GAP_JITTER_SECONDS),
        "in_flight_pairs": 0,
        "in_flight_total": 0,
        "rejected_total": 0,
    }
    if middleware is not None:
        status.update(middleware.concurrency_snapshot())
    return status


def attach(mcp, store, state, settings=None) -> UsageAndFlagsMiddleware | None:
    """Attach the middleware exactly once to a FastMCP instance."""
    try:
        existing = getattr(mcp, "_kxstrel_usage_middleware", None)
        if existing is not None:
            return existing
        mw = UsageAndFlagsMiddleware(store, state, settings=settings)
        mcp.add_middleware(mw)
        mcp._kxstrel_usage_middleware = mw  # type: ignore[attr-defined]
        log.info("usage/flags middleware attached to spectre server")
        return mw
    except Exception as exc:
        log.warning("middleware attach failed (usage logging disabled): %s",
                    sanitize_error(str(exc)))
        return None
