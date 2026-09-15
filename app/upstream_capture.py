"""Diagnostic capture of upstream GraphQL write responses.

Spectre reports success for some write operations even though nothing
observable happens on the X side (``createBookmarkFolder``,
``CreateHighlight``, ``DeleteHighlight``, ``FollowUser``). To see what X
actually replies, this module wraps the single choke point for GraphQL
writes — ``spectre.writer.Writer._post`` — and records, in memory only, the
operation name, the parsed request ``variables`` and the parsed response
dict.

Design constraints that keep this safe:

- **Off by default.** The wrap is installed only when an admin first enables
  capture; the enabled-flag lives on the module-level :class:`CaptureState`.
  At import time nothing is touched and nothing is recorded.
- **Pure pass-through.** The wrap returns the exact value the original call
  returns and lets exceptions propagate unchanged; on the success path it
  performs one flag check and one bounded append after the call.
- **Secret-safe.** Only the parsed ``variables`` and parsed response dict are
  stored (never headers, auth tokens, transport bodies). Both are run through
  ``app.logging_setup.redact`` before being appended.
- **Bounded.** A fixed-size ring buffer (50 entries) drops the oldest entry
  when full.

Note: the literal word "cookie" is deliberately absent from every key and
docstring exported by this module so the admin-surface secret tripwire stays
meaningful.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone

from .logging_setup import redact

CAPACITY = 50


def _redact_value(value):
    """Recursively run every string leaf through the shared redaction helper.

    Serializing to JSON, redacting the string and re-parsing would corrupt the
    document when the assignment scrubber rewrites ``"auth_token": "…"`` into
    ``auth_token=[redacted]``. Walking the structure keeps valid, structured
    JSON while still applying the exact same ``redact`` rules to each value.
    """
    if isinstance(value, dict):
        return {redact(k) if isinstance(k, str) else k: _redact_value(v)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(v) for v in value]
    if isinstance(value, str):
        return redact(value)
    return value


class CaptureState:
    """In-memory ring buffer plus the enabled flag the wrap checks per call."""

    def __init__(self, capacity: int = CAPACITY):
        self._capacity = capacity
        self._lock = threading.Lock()
        self.enabled = False
        self.operations: frozenset[str] | None = None  # None = capture all
        # Newest entries are at the front; deque(maxlen=…) drops the oldest
        # automatically when the buffer is full.
        self._buffer: deque[dict] = deque(maxlen=capacity)

    def enable(self, operations: list[str] | None = None) -> None:
        """Enable capture, optionally restricted to the given operation names."""
        ops: frozenset[str] | None = None
        if operations:
            ops = frozenset(str(o) for o in operations)
        with self._lock:
            self.enabled = True
            self.operations = ops
            self._buffer.clear()

    def disable(self) -> None:
        """Disable capture and clear whatever was buffered."""
        with self._lock:
            self.enabled = False
            self.operations = None
            self._buffer.clear()

    def record(self, operation: str, variables: dict, response: dict) -> None:
        """Store one capture entry if capture is enabled and the operation
        matches the filter. Called by the wrap only after a successful call."""
        if not self.enabled:
            return
        operations = self.operations
        if operations is not None and operation not in operations:
            return
        entry = {
            "operation": operation,
            "variables": _redact_value(variables),
            "response": _redact_value(response),
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._buffer.appendleft(entry)

    def snapshot(self) -> list[dict]:
        """Newest-first list of captured entries."""
        with self._lock:
            return list(self._buffer)

    def summary(self) -> dict:
        """Current state for the admin API: enabled, filter, entry count."""
        with self._lock:
            operations = None if self.operations is None else sorted(self.operations)
            return {
                "enabled": self.enabled,
                "operations": operations,
                "count": len(self._buffer),
            }


# Module-level singleton: the flag the wrap reads, and the buffer the admin
# API exposes. Installed once per process; never touched at import.
_state = CaptureState()
_hook_installed = False


def install_hook() -> None:
    """Wrap the spectre writer singleton's ``_post`` bound method.

    Idempotent: after the first install the wrap stays in place for the life
    of the process, and the enabled-flag on :class:`CaptureState` decides
    whether anything is recorded. This must never run at import time — only
    the enable route calls it.
    """
    global _hook_installed
    if _hook_installed:
        return
    from spectre.server import _get_writer

    writer = _get_writer()
    original = writer._post  # bound method; capture before shadowing

    async def _wrapped_post(operation, variables, features=None, field_toggles=None):
        # Identical return value, exception and await structure to the
        # original: call it first, record only on success, re-raise unchanged.
        result = await original(operation, variables,
                                features=features, field_toggles=field_toggles)
        _state.record(operation, variables, result)
        return result

    writer._post = _wrapped_post  # instance attribute shadows the class method
    _hook_installed = True


def enable(operations: list[str] | None = None) -> None:
    """Enable capture (installs the wrap first) and clear the buffer."""
    install_hook()
    _state.enable(operations)


def disable() -> None:
    """Disable capture and clear the buffer."""
    _state.disable()


def snapshot() -> list[dict]:
    return _state.snapshot()


def summary() -> dict:
    return _state.summary()
