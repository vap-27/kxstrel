"""Versioned snapshots of the critical tables to a second store.

Primary (TiDB/Postgres/sqlite) -> backup (Postgres-compatible, e.g.
CockroachDB). Every run writes a NEW snapshot instead of overwriting the last
one: an index row in ``backup_snapshots`` plus the full ``x_accounts`` rows
(encrypted credentials included), the primary's ``schema_migrations``,
``tool_flags`` and ``admin_audit`` rows, all keyed by that run's snapshot
timestamp. A bad state on the primary therefore cannot destroy the previous
good copy — the old design mirrored in place and did exactly that.

Retention: snapshots older than ``BACKUP_RETENTION_DAYS`` (default 10) are
pruned after each successful run, from the index and from every snapshot
table so no orphan rows are left. A pruning failure never fails the run.

Usage logs are operational telemetry and stay on the primary store with their
own retention pruning.

The only code path that writes a snapshot back into the PRIMARY store is the
explicit admin restore (``POST /admin/api/backup/restore``); see
SessionMonitor for the read-only fallback the gateway uses at boot.

The tables the older, overwrite-in-place mirror design created in the backup
store (``x_accounts``, ``tool_flags``, ``admin_audit`` *there*) are left in
place but unused: dropping them would be destructive and a store may still
hold the last mirrored copy of an account.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from .db import AccountStore
from .logging_setup import get_logger, sanitize_error
from .models import GatewayState

log = get_logger("kxstrel-x-mcp.backup")

# Every snapshot partition; pruning and discarding have to touch all of them
# together or rows would be orphaned.
SNAPSHOT_TABLES = (
    "backup_accounts",
    "backup_schema_migrations",
    "backup_tool_flags",
    "backup_admin_audit",
)


class BackupManager:
    def __init__(self, backup_store: AccountStore | None, state: GatewayState,
                 retention_days: int = 10):
        self.store = backup_store
        self.state = state
        # A zero or negative window would delete the snapshot the run just
        # wrote, so the floor is one day.
        self.retention_days = max(1, int(retention_days))
        self._lock = asyncio.Lock()
        self._primary: AccountStore | None = None
        self._last_snapshot_at: str | None = None

    def bind_primary(self, primary: AccountStore) -> None:
        self._primary = primary

    # ── run ────────────────────────────────────────────────────────────
    def _next_snapshot_at(self) -> str:
        """Strictly increasing UTC ISO-8601 timestamp with microseconds.

        Microsecond resolution keeps two runs from colliding, and the
        monotonic guard covers a clock that steps backwards. The primary key
        on ``backup_snapshots.snapshot_at`` turns any remaining collision
        into a failed run rather than two runs merged into one snapshot."""
        now = datetime.now(timezone.utc)
        if self._last_snapshot_at is not None:
            previous = datetime.fromisoformat(self._last_snapshot_at)
            if now <= previous:
                now = previous + timedelta(microseconds=1)
        self._last_snapshot_at = now.isoformat()
        return self._last_snapshot_at

    async def run(self, triggered_by: str) -> dict:
        if self.store is None:
            return {"ok": False, "error": "BACKUP_DATABASE_URL is not configured"}
        if self._lock.locked():
            return {"ok": False, "error": "backup already in progress"}
        async with self._lock:
            return await self._run_locked(triggered_by)

    async def _run_locked(self, triggered_by: str) -> dict:
        started = datetime.now(timezone.utc)
        snapshot_at = self._next_snapshot_at()
        self.state.last_backup_attempt_at = started.isoformat()
        try:
            # The primary store is injected by the caller via bind_primary().
            primary = self._primary
            accounts = await primary.dump_accounts()
            migrations = await primary.dump_schema_migrations()
            flags = await primary.dump_tool_flags()
            audit = await primary.dump_admin_audit()

            await self.store.init_schema()
            # The index row is the authoritative claim for this run: written
            # before any row of the snapshot, so a duplicate id fails here
            # instead of silently merging two runs into one partition.
            await self.store._exec(
                "INSERT INTO backup_snapshots (snapshot_at, created_at, triggered_by,"
                " account_rows, migration_rows, tool_flag_rows, audit_rows)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (snapshot_at, started.isoformat(), triggered_by, len(accounts),
                 len(migrations), len(flags), len(audit)),
            )
            try:
                await self._write_snapshot(snapshot_at, accounts, migrations, flags, audit)
            except BaseException:
                # A half-written snapshot must never be picked up by the
                # fallback (which reads the NEWEST one), so drop it entirely.
                await self._discard_snapshot(snapshot_at)
                raise

            prune = await self._prune()
            result = {
                "ok": True,
                "snapshot_at": snapshot_at,
                "accounts": len(accounts),
                "schema_migrations": len(migrations),
                "tool_flags": len(flags),
                "admin_audit": len(audit),
                "pruned": prune["pruned"],
                "oldest_snapshot_at": prune["oldest_remaining"],
                "retention_days": self.retention_days,
                "duration_ms": int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
            }
            if prune.get("error"):
                # The snapshot itself succeeded; only the retention sweep
                # failed. Say so without turning the run into a failure.
                result["prune_error"] = prune["error"]
            self.state.backup_ok = True
            self.state.last_backup_at = datetime.now(timezone.utc).isoformat()
            self.state.last_backup_snapshot_at = snapshot_at
            self.state.last_backup_error = None
            # Persist the successful cursor so a restart does not lose the
            # operational backup history shown by the dashboard.
            await primary.set_meta("last_backup_success_at", self.state.last_backup_at)
            log.info("backup complete (%s): %s", triggered_by, result)
            return result
        except Exception as exc:
            err = sanitize_error(str(exc))
            self.state.backup_ok = False
            self.state.last_backup_attempt_at = datetime.now(timezone.utc).isoformat()
            self.state.last_backup_error = err
            log.warning("backup failed (%s): %s", triggered_by, err)
            return {"ok": False, "error": err, "snapshot_at": snapshot_at}

    async def _write_snapshot(self, snapshot_at: str, accounts: list[dict],
                              migrations: list[dict], flags: list[dict],
                              audit: list[dict]) -> None:
        """Insert every row of one snapshot. Rows are never updated in place:
        an already-written snapshot stays byte-for-byte as it was."""
        for row in accounts:
            await self.store._exec(
                "INSERT INTO backup_accounts (snapshot_at, label, enc_auth_token,"
                " enc_ct0, enabled, status, last_checked_at, last_check_ok,"
                " last_error, meta, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (snapshot_at, row["label"], row["enc_auth_token"], row["enc_ct0"],
                 int(bool(row["enabled"])), row.get("status"), row.get("last_checked_at"),
                 None if row.get("last_check_ok") is None else int(bool(row["last_check_ok"])),
                 row.get("last_error"), row.get("meta") or "{}",
                 row.get("created_at"), row.get("updated_at")),
            )
        for row in migrations:
            await self.store._exec(
                "INSERT INTO backup_schema_migrations (snapshot_at, version, name, applied_at)"
                " VALUES (?, ?, ?, ?)",
                (snapshot_at, int(row["version"]), row.get("name"), row.get("applied_at")),
            )
        for row in flags:
            await self.store._exec(
                "INSERT INTO backup_tool_flags (snapshot_at, tool_name, enabled, updated_at)"
                " VALUES (?, ?, ?, ?)",
                (snapshot_at, row["tool_name"], int(bool(row["enabled"])), row.get("updated_at")),
            )
        for row in audit:
            # No dedupe pass: each snapshot is its own partition, so an audit
            # row appears exactly once per run by construction. (The audit
            # re-insert in restore() still dedupes against the primary, which
            # is what keeps running a restore twice idempotent.)
            await self.store._exec(
                "INSERT INTO backup_admin_audit (snapshot_at, ts, action, detail, request_id)"
                " VALUES (?, ?, ?, ?, ?)",
                (snapshot_at, row.get("ts"), row.get("action"), row.get("detail"),
                 row.get("request_id")),
            )

    # ── retention ──────────────────────────────────────────────────────
    async def _prune(self) -> dict:
        """Delete every snapshot outside the retention window.

        Snapshot rows are removed before the index row they belong to, so a
        crash mid-prune can only leave an index row without rows (which the
        next prune finishes) and never a child row without an index row.
        Never raises: a retention failure must not fail a successful backup.
        """
        try:
            cutoff = (datetime.now(timezone.utc)
                      - timedelta(days=self.retention_days)).isoformat()
            expired = {row["snapshot_at"] for row in await self.store._fetch_all(
                "SELECT snapshot_at FROM backup_snapshots WHERE snapshot_at < ?", (cutoff,))}
            # Child rows whose index row already vanished (a crash between the
            # two deletes) are pruned as well, so nothing is left orphaned.
            for table in SNAPSHOT_TABLES:
                rows = await self.store._fetch_all(
                    f"SELECT DISTINCT snapshot_at FROM {table} WHERE snapshot_at < ?", (cutoff,))
                expired.update(row["snapshot_at"] for row in rows)
            for snapshot_at in sorted(expired):
                await self._delete_snapshot_rows(snapshot_at)
            oldest = await self.store._fetch_one(
                "SELECT snapshot_at FROM backup_snapshots ORDER BY snapshot_at ASC")
            oldest_at = oldest["snapshot_at"] if oldest else None
            if expired:
                log.info("backup retention: pruned %d snapshot(s) older than %d day(s);"
                         " oldest remaining=%s", len(expired), self.retention_days, oldest_at)
            return {"pruned": len(expired), "oldest_remaining": oldest_at}
        except Exception as exc:
            err = sanitize_error(str(exc))
            log.warning("backup retention prune failed (snapshot kept): %s", err)
            return {"pruned": 0, "oldest_remaining": None, "error": err}

    async def _delete_snapshot_rows(self, snapshot_at: str) -> None:
        for table in SNAPSHOT_TABLES:
            await self.store._exec(
                f"DELETE FROM {table} WHERE snapshot_at = ?", (snapshot_at,))
        await self.store._exec(
            "DELETE FROM backup_snapshots WHERE snapshot_at = ?", (snapshot_at,))

    async def _discard_snapshot(self, snapshot_at: str) -> None:
        try:
            await self._delete_snapshot_rows(snapshot_at)
        except Exception as exc:  # pragma: no cover - cleanup is best-effort
            log.warning("could not discard the partial snapshot %s: %s",
                        snapshot_at, sanitize_error(str(exc)))

    async def delete_snapshot(self, snapshot_at: str) -> bool:
        """Delete one snapshot partition and its index row explicitly."""
        if self.store is None:
            return False
        if not await self.snapshot_exists(snapshot_at):
            return False
        await self._delete_snapshot_rows(snapshot_at)
        return True

    # ── reading snapshots (fallback + restore) ─────────────────────────
    async def latest_snapshot(self) -> str | None:
        row = await self.store._fetch_one(
            "SELECT snapshot_at FROM backup_snapshots ORDER BY snapshot_at DESC")
        return row["snapshot_at"] if row else None

    async def list_snapshots(self, limit: int = 20) -> list[dict]:
        return await self.store._fetch_all(
            "SELECT snapshot_at, created_at, triggered_by, account_rows, migration_rows,"
            " tool_flag_rows, audit_rows FROM backup_snapshots"
            " ORDER BY snapshot_at DESC LIMIT ?", (int(limit),),
        )

    async def snapshot_accounts(self, snapshot_at: str) -> list[dict]:
        return await self.store._fetch_all(
            "SELECT * FROM backup_accounts WHERE snapshot_at = ? ORDER BY label",
            (snapshot_at,),
        )

    async def snapshot_exists(self, snapshot_at: str) -> bool:
        row = await self.store._fetch_one(
            "SELECT snapshot_at FROM backup_snapshots WHERE snapshot_at = ?", (snapshot_at,))
        return row is not None

    async def newest_snapshot_accounts(self) -> tuple[str | None, list[dict]]:
        """The newest snapshot's account rows, or ``(None, [])`` when the
        backup store holds no snapshot at all."""
        snapshot_at = await self.latest_snapshot()
        if snapshot_at is None:
            return None, []
        return snapshot_at, await self.snapshot_accounts(snapshot_at)

    async def account_from_newest_snapshot(self, label: str) -> dict | None:
        """The newest snapshot row for one label (corrupt-row fallback)."""
        return await self.store._fetch_one(
            "SELECT * FROM backup_accounts WHERE label = ? ORDER BY snapshot_at DESC",
            (label,),
        )

    # ── explicit restore (the only write back into the primary) ────────
    async def restore_snapshot(self, snapshot_at: str | None = None) -> dict:
        """Write one snapshot back into the PRIMARY store.

        Deliberately the only path that writes a snapshot into the primary, so
        resurrecting a deleted account is always an explicit operator action
        and never something the gateway does on its own.

        Accounts present in the snapshot are upserted (with their status
        columns as captured) and accounts that exist only on the primary are
        left alone: a restore repairs and resurrects, it never deletes. Audit
        rows are re-inserted idempotently, so running a restore twice does not
        duplicate them.
        """
        if self.store is None or self._primary is None:
            return {"ok": False, "error": "BACKUP_DATABASE_URL is not configured"}
        snapshot_at = snapshot_at or await self.latest_snapshot()
        if not snapshot_at:
            return {"ok": False, "not_found": True, "error": "no snapshots available"}
        try:
            if not await self.snapshot_exists(snapshot_at):
                return {"ok": False, "snapshot_at": snapshot_at, "not_found": True,
                        "error": f"snapshot {snapshot_at} does not exist"}
            # A snapshot may legitimately hold zero accounts (the primary had
            # none when it ran); its flags and audit rows are still restored.
            accounts = await self.snapshot_accounts(snapshot_at)
            flags = await self.store._fetch_all(
                "SELECT tool_name, enabled FROM backup_tool_flags WHERE snapshot_at = ?",
                (snapshot_at,),
            )
            audit = await self.store._fetch_all(
                "SELECT ts, action, detail, request_id FROM backup_admin_audit"
                " WHERE snapshot_at = ?", (snapshot_at,),
            )
            primary = self._primary
            for row in accounts:
                await primary.upsert_account(
                    row["label"], row["enc_auth_token"], row["enc_ct0"],
                    enabled=bool(row["enabled"]), meta=row.get("meta") or "{}",
                )
                # Preserve the operational columns the upsert does not carry.
                await primary._exec(
                    "UPDATE x_accounts SET status=?, last_checked_at=?, last_check_ok=?,"
                    " last_error=?, created_at=?, updated_at=? WHERE label=?",
                    (row.get("status"), row.get("last_checked_at"), row.get("last_check_ok"),
                     row.get("last_error"), row.get("created_at"), row.get("updated_at"),
                     row["label"]),
                )
            for row in flags:
                await primary.set_tool_flag(row["tool_name"], bool(row["enabled"]))
            existing = {(r["ts"], r["action"], r.get("request_id"))
                        for r in await primary.dump_admin_audit()}
            audit_restored = 0
            for row in audit:
                key = (row.get("ts"), row.get("action"), row.get("request_id"))
                if key in existing:
                    continue
                await primary._exec(
                    "INSERT INTO admin_audit (ts, action, detail, request_id) VALUES (?, ?, ?, ?)",
                    (row.get("ts"), row.get("action"), row.get("detail"), row.get("request_id")),
                )
                existing.add(key)
                audit_restored += 1
            log.info("snapshot restore: snapshot_at=%s accounts=%d tool_flags=%d audit_rows=%d",
                     snapshot_at, len(accounts), len(flags), audit_restored)
            return {
                "ok": True,
                "snapshot_at": snapshot_at,
                "accounts": len(accounts),
                "tool_flags": len(flags),
                "admin_audit": audit_restored,
            }
        except Exception as exc:
            err = sanitize_error(str(exc))
            log.warning("snapshot restore failed snapshot_at=%s: %s", snapshot_at, err)
            return {"ok": False, "snapshot_at": snapshot_at, "error": err}
