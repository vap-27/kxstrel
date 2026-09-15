"""Lightweight background X-session health checking + housekeeping.

- Fixed cadence, clamped to >= 300s: no aggressive traffic, no busy loops.
- One cheap authenticated call per enabled account per cycle.
- Failures only flip recorded status; the service keeps serving and /status
  reports the problem. No browser login is ever attempted, no retries storm.
- Also drives usage-log pruning (daily) and scheduled backups.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from .crypto import CredentialCrypto
from .db import AccountStore
from .logging_setup import get_logger, sanitize_error
from .models import AccountRecord, GatewayState, XStatus
from .spectre_adapter import SpectreAdapter

log = get_logger("kxstrel-x-mcp.monitor")

MIN_INTERVAL_SECONDS = 300

# "Worst problem wins" when no account is connected.
_PROBLEM_ORDER = [
    XStatus.INVALID_SESSION,
    XStatus.RATE_LIMITED,
    XStatus.X_UNAVAILABLE,
    XStatus.CONFIG_ERROR,
    XStatus.NOT_CONFIGURED,
]


def aggregate_status(statuses: list[XStatus]) -> XStatus:
    if not statuses:
        return XStatus.NOT_CONFIGURED
    if XStatus.CONNECTED in statuses:
        return XStatus.CONNECTED
    for problem in _PROBLEM_ORDER:
        if problem in statuses:
            return problem
    return XStatus.CONFIG_ERROR


class SessionMonitor:
    def __init__(
        self,
        store: AccountStore,
        crypto: CredentialCrypto | None,
        adapter: SpectreAdapter,
        state: GatewayState,
        interval_seconds: int,
        timeout_seconds: float,
        backup_manager=None,
        backup_interval_hours: int = 24,
        retention_days: int = 30,
    ):
        self.store = store
        self.crypto = crypto
        self.adapter = adapter
        self.state = state
        self.interval = max(MIN_INTERVAL_SECONDS, interval_seconds)
        self.timeout = timeout_seconds
        self.backup_manager = backup_manager
        self.backup_interval_hours = max(1, backup_interval_hours)
        self.retention_days = max(1, retention_days)
        self._task: asyncio.Task | None = None
        self._admin_sessions_ref = None

    def bind_sessions(self, sessions) -> None:
        self._admin_sessions_ref = sessions

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="x-session-monitor")
            log.info("session monitor started interval=%ss", self.interval)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
            log.info("session monitor stopped")

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self.interval)
            try:
                await self.check_once(source="background")
            except Exception as exc:
                log.warning("background session check failed: %s", sanitize_error(str(exc)))
            try:
                await self._housekeeping()
            except Exception as exc:
                log.warning("background housekeeping failed: %s", sanitize_error(str(exc)))

    # -- housekeeping -----------------------------------------------------
    async def _housekeeping(self) -> None:
        now = datetime.now(timezone.utc)
        # Expired local admin sessions (bounded memory; Redis self-expires).
        sessions = getattr(self, "_admin_sessions_ref", None)
        if sessions is not None:
            sessions.prune_local()
        # Usage-log prune: at most once a day.
        last_prune = self.state.last_prune_at
        if last_prune is None or (now - datetime.fromisoformat(last_prune)).total_seconds() > 86400:
            try:
                removed = await self.store.prune_tool_usage(self.retention_days)
                self.state.last_prune_at = now.isoformat()
                log.info("usage logs pruned (retention=%sd): %s rows touched",
                         self.retention_days, removed)
            except Exception as exc:
                log.warning("usage prune failed: %s", sanitize_error(str(exc)))
        # Scheduled backup: honor the configured interval. Failed attempts
        # remain retryable because last_backup_at only records success.
        last_backup = self.state.last_backup_at or self.state.last_backup_attempt_at
        due = (last_backup is None or
               (now - datetime.fromisoformat(last_backup)).total_seconds()
               >= self.backup_interval_hours * 3600)
        if self.backup_manager is not None and due:
            await self.backup_manager.run(triggered_by="schedule")

    def _backup_due(self) -> bool:
        last_backup = self.state.last_backup_at or self.state.last_backup_attempt_at
        if self.backup_manager is None or last_backup is None:
            return self.backup_manager is not None
        return (datetime.now(timezone.utc) - datetime.fromisoformat(last_backup)).total_seconds() \
            >= self.backup_interval_hours * 3600

    # -- session checks -----------------------------------------------------
    async def _accounts_to_serve(self) -> tuple[list, str | None, bool]:
        """Enabled accounts to (re)build the pool from, plus the snapshot
        timestamp when they came from the backup store instead, plus whether
        the primary store answered at all.

        The fallback is deliberately narrow: the primary store stays
        authoritative whenever it is reachable AND holds at least one account
        row — including the case where every account is disabled, which is a
        decision, not an outage. Only an unreachable store, or one with no
        account rows at all, may be served from the newest snapshot.
        """
        rows = None
        try:
            rows = await self.store.get_all_accounts()
        except Exception as exc:
            log.warning("session check: primary store unreadable: %s", sanitize_error(str(exc)))
        if rows:
            return [r for r in rows if r.enabled], None, True
        if self.backup_manager is None:
            return [], None, rows is not None
        try:
            snapshot_at, snapshot_rows = await self.backup_manager.newest_snapshot_accounts()
        except Exception as exc:
            log.warning("session check: backup snapshot unreadable: %s", sanitize_error(str(exc)))
            return [], None, rows is not None
        enabled = [self._record_from_snapshot(r) for r in snapshot_rows if r.get("enabled")]
        if not enabled:
            return [], None, rows is not None
        log.warning("session check: primary store yielded no accounts; serving %d account(s) "
                    "from backup snapshot %s (primary is NOT written)",
                    len(enabled), snapshot_at)
        return enabled, snapshot_at, True

    @staticmethod
    def _record_from_snapshot(row: dict):
        """A snapshot row as the monitor's normal account record. Ciphertext
        only: nothing is decrypted here and nothing is written anywhere."""
        return AccountRecord(
            id=None,
            label=row["label"],
            enc_auth_token=row["enc_auth_token"],
            enc_ct0=row["enc_ct0"],
            enabled=bool(row["enabled"]),
            status=row.get("status") or XStatus.NOT_CONFIGURED.value,
            last_checked_at=row.get("last_checked_at"),
            last_check_ok=None if row.get("last_check_ok") is None else bool(row["last_check_ok"]),
            last_error=row.get("last_error"),
            meta=row.get("meta") or "{}",
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
        )

    async def _decrypt_snapshot_credential(self, label: str):
        """The newest snapshot's credentials for one label, decrypted.

        Reached ONLY when the stored row cannot be decrypted (a corrupt or
        wrongly-keyed row). It is deliberately not consulted when validation
        merely reports an expired/invalid session: expired is expired, and
        silently reusing older cookies would mask a real outage and confuse
        the operator. Returns (auth_token, ct0, snapshot_at) or None."""
        if self.backup_manager is None:
            return None
        try:
            row = await self.backup_manager.account_from_newest_snapshot(label)
            if row is None:
                return None
            return (
                self.crypto.decrypt(row["enc_auth_token"]),
                self.crypto.decrypt(row["enc_ct0"]),
                row["snapshot_at"],
            )
        except Exception as exc:
            log.warning("account %s: snapshot credential unusable too: %s",
                        label, sanitize_error(str(exc)))
            return None

    async def check_once(self, source: str = "manual", validate: bool = True) -> dict[str, str]:
        """Validate every enabled account once. Returns {label: status}."""
        if self.crypto is None:
            log.warning("session check (%s) skipped: no credential crypto", source)
            return {}
        accounts: list = []
        restored_from: str | None = None
        store_ok = False
        try:
            accounts, restored_from, store_ok = await self._accounts_to_serve()
        except Exception as exc:
            log.warning("session check (%s): account lookup failed: %s",
                        source, sanitize_error(str(exc)))
        restored_labels: list[str] = []
        credential_snapshot_at: str | None = None
        results: dict[str, str] = {}
        statuses: list[XStatus] = []
        for acct in accounts:
            # Serialize pool mutation/checking with admin account operations,
            # and re-check enabled state after the DB read to avoid re-adding
            # an account that was disabled while this cycle was waiting.
            async with self.adapter.operation_lock:
                if restored_from is None and not await self.store.is_account_enabled(acct.label):
                    continue
                credential_source = "primary"
                try:
                    auth_token = self.crypto.decrypt(acct.enc_auth_token)
                    ct0 = self.crypto.decrypt(acct.enc_ct0)
                except Exception:
                    recovered = (None if restored_from is not None
                                 else await self._decrypt_snapshot_credential(acct.label))
                    if recovered is None:
                        if restored_from is None:
                            await self._record_status(acct.label, XStatus.CONFIG_ERROR.value,
                                                      False, "stored credential undecryptable")
                        statuses.append(XStatus.CONFIG_ERROR)
                        results[acct.label] = XStatus.CONFIG_ERROR.value
                        continue
                    auth_token, ct0, snapshot_at = recovered
                    credential_source = f"snapshot:{snapshot_at}"
                    credential_snapshot_at = snapshot_at
                    restored_labels.append(acct.label)
                    log.warning("account %s: stored credential is corrupt; using the newest "
                                "snapshot copy (snapshot_at=%s). The primary row is left as it "
                                "is; POST /admin/api/backup/restore repairs it explicitly.",
                                acct.label, snapshot_at)
                try:
                    await self.adapter._sync_account(acct.label, auth_token, ct0)
                except Exception as exc:
                    err = sanitize_error(str(exc))
                    if restored_from is None and credential_source == "primary":
                        await self._record_status(acct.label, XStatus.X_UNAVAILABLE.value, False, err)
                    statuses.append(XStatus.X_UNAVAILABLE)
                    results[acct.label] = XStatus.X_UNAVAILABLE.value
                    continue
                if validate:
                    status, detail = await self.adapter._validate(acct.label, self.timeout)
                    if restored_from is None and credential_source == "primary":
                        await self._record_status(acct.label, status.value,
                                                  status == XStatus.CONNECTED, detail)
                else:
                    try:
                        status = XStatus(acct.status)
                    except ValueError:
                        status = XStatus.NOT_CONFIGURED
            statuses.append(status)
            results[acct.label] = status.value
        previous = self.state.x_status
        if not accounts and not store_ok:
            # The store could not be read AND no snapshot could stand in:
            # "not configured" would be a lie, the accounts are simply
            # unreachable right now.
            statuses.append(XStatus.CONFIG_ERROR)
        self.state.x_status = aggregate_status(statuses)
        self.state.last_checked_at = datetime.now(timezone.utc).isoformat()
        # The newest snapshot the pool was hydrated from — whole accounts
        # (store-level fallback) or single corrupt rows (restored_labels).
        self.state.restored_from_snapshot = restored_from or credential_snapshot_at
        self.state.restored_labels = restored_labels
        if restored_from is not None:
            # The running account count describes what the gateway is
            # actually serving; the primary could not answer.
            self.state.accounts_configured = len(accounts)
            self.state.accounts_enabled = len(accounts)
        failing = [f"{k}={v}" for k, v in results.items() if v != XStatus.CONNECTED.value]
        if not accounts and not store_ok:
            failing.append("account store unreadable, no snapshot to serve from")
        self.state.last_error = "; ".join(failing)[:300] if failing else None
        if self.state.x_status != previous:
            log.info("x session status %s -> %s (%s)", previous.value, self.state.x_status.value, source)
        from . import metrics_setup

        metrics_setup.observe_x_status(self.state.x_status.value)
        return results

    async def _record_status(self, label: str, status: str, ok: bool | None,
                             error: str | None) -> None:
        """Status writes are best-effort: they must not abort a check cycle."""
        try:
            await self.store.update_status(label, status, ok, error)
        except Exception as exc:
            log.debug("status update failed label=%s: %s", label, sanitize_error(str(exc)))
