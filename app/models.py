"""Shared domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class XStatus(str, Enum):
    CONNECTED = "CONNECTED"
    INVALID_SESSION = "INVALID_SESSION"
    RATE_LIMITED = "RATE_LIMITED"
    X_UNAVAILABLE = "X_UNAVAILABLE"
    CONFIG_ERROR = "CONFIG_ERROR"
    NOT_CONFIGURED = "NOT_CONFIGURED"


@dataclass
class AccountRecord:
    id: int | None
    label: str
    enc_auth_token: str
    enc_ct0: str
    enabled: bool
    status: str
    last_checked_at: str | None
    last_check_ok: bool | None
    last_error: str | None
    meta: str
    created_at: str | None
    updated_at: str | None


@dataclass
class GatewayState:
    """Mutable operational snapshot served by /status and /diagnostics."""

    x_status: XStatus = XStatus.NOT_CONFIGURED
    db_ok: bool = False
    db_backend: str = "unknown"
    # Why the primary store is not usable (closed-set kind + a one-line hint
    # naming the concrete thing to check; see app/db_resilience.py). Both are
    # None once a connection succeeded, and the message is always
    # sanitized — never a DSN, a password or a raw driver dump.
    db_error_kind: str | None = None
    db_error: str | None = None
    db_hint: str | None = None
    mcp_ok: bool = False
    tool_count: int = 0
    tool_names: list[str] = field(default_factory=list)
    spectre_version: str = "unknown"
    spectre_pin: str = "unknown"
    spectre_version_ok: bool = False
    accounts_configured: int = 0
    accounts_enabled: int = 0
    last_checked_at: str | None = None
    last_error: str | None = None
    started_at: str | None = None
    policy_ready: bool = False
    # backups
    backup_ok: bool | None = None
    backup_backend: str = "none"
    last_backup_at: str | None = None
    last_backup_error: str | None = None
    last_backup_attempt_at: str | None = None
    last_backup_snapshot_at: str | None = None
    # Snapshot fallback: the newest snapshot timestamp the pool was hydrated
    # from when the primary store could not provide the accounts (None when
    # the primary is authoritative, i.e. the normal case). Purely
    # informational — the primary is never written by this path.
    restored_from_snapshot: str | None = None
    restored_labels: list[str] = field(default_factory=list)
    # housekeeping
    last_prune_at: str | None = None
    # persisted uptime markers (never reset by restarts/refreshes)
    service_first_started_at: str | None = None
    mcp_first_ok_at: str | None = None
