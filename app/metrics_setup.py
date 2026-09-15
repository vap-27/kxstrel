"""Prometheus metrics (admin-gated /metrics endpoint)."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

http_requests_total = Counter(
    "kxstrel_http_requests_total", "HTTP requests", ["path", "status"]
)
tool_calls_total = Counter(
    "kxstrel_tool_calls_total", "MCP tool calls", ["tool", "ok"]
)
admin_actions_total = Counter(
    "kxstrel_admin_actions_total", "Admin panel actions", ["action"]
)
tool_duration_ms = Histogram(
    "kxstrel_tool_duration_ms", "Tool call duration (ms)",
    buckets=(50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000)
)
x_status_value = Gauge(
    "kxstrel_x_session_ok", "1 when the X session reports CONNECTED"
)
db_ok_value = Gauge(
    "kxstrel_db_ok", "1 when the primary database answers pings"
)


def observe_x_status(status: str) -> None:
    x_status_value.set(1 if status == "CONNECTED" else 0)


def observe_db_ok(ok: bool) -> None:
    db_ok_value.set(1 if ok else 0)
