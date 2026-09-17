"""Versioned backup snapshots, retention pruning, and the two fallbacks.

The backup store used to be a mirror: every run overwrote the previous one, so
a bad state on the primary was copied over the last good copy. These tests pin
the replacement contract:

  * a run APPENDS a snapshot — the previous one stays queryable and unchanged;
  * snapshots outside ``BACKUP_RETENTION_DAYS`` are pruned (index + rows, no
    orphans) and a pruning failure never fails the run;
  * the store-level fallback hydrates the pool from the newest snapshot only
    when the primary is unreachable or holds no account at all, and never
    writes the primary;
  * the per-account fallback triggers on a DECRYPT failure only — an expired
    session is never papered over with older cookies;
  * the restore route is admin-gated + CSRF-guarded, defaults to the newest
    snapshot, and is the only path that writes a snapshot into the primary.

Everything here is deterministic and offline: sqlite stores, a fake adapter.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.backup import SNAPSHOT_TABLES, BackupManager
from app.config import Settings
from app.crypto import CredentialCrypto
from app.db import AccountStore
from app.models import GatewayState, XStatus
from app.session_monitor import SessionMonitor

ROOT = Path(__file__).resolve().parent.parent
ADMIN = {"Authorization": f"Bearer {os.environ['ADMIN_TOKEN']}"}
MCP = {"Authorization": f"Bearer {os.environ['MCP_ACCESS_TOKEN']}"}


def _url(tmp_path, name: str) -> str:
    return f"sqlite:///{tmp_path / name}"


async def _stores(tmp_path, *, seed: bool = True):
    """A primary + backup sqlite store pair, connected and migrated."""
    primary = AccountStore(_url(tmp_path, "primary.db"))
    backup = AccountStore(_url(tmp_path, "backup.db"))
    for store in (primary, backup):
        await store.connect()
        await store.init_schema()
    if seed:
        await primary.upsert_account("acct1", "ENC-A1", "ENC-C1", enabled=True)
        await primary.set_tool_flag("get_trends", False)
        await primary.log_admin_action("login_ok", "detail", "req-1")
    return primary, backup


def _manager(backup, state, retention_days: int = 10) -> BackupManager:
    manager = BackupManager(backup, state, retention_days=retention_days)
    return manager


def _crypto() -> CredentialCrypto:
    return CredentialCrypto(Fernet.generate_key().decode())


class _FakeAdapter:
    """Stands in for SpectreAdapter: records pool syncs, never touches X."""

    def __init__(self, status: XStatus = XStatus.CONNECTED):
        self.operation_lock = asyncio.Lock()
        self.status = status
        self.synced: list[tuple[str, str, str]] = []
        self.validated = 0

    async def _sync_account(self, label: str, auth_token: str, ct0: str) -> bool:
        self.synced.append((label, auth_token, ct0))
        return True

    async def _validate(self, label: str, timeout: float):
        self.validated += 1
        return self.status, None


def _monitor(primary, crypto, adapter, state, manager=None) -> SessionMonitor:
    return SessionMonitor(primary, crypto, adapter, state, interval_seconds=3600,
                          timeout_seconds=5, backup_manager=manager)


# ── append-only snapshots ────────────────────────────────────────────────

def test_a_run_appends_a_snapshot_and_leaves_the_previous_one_intact(tmp_path):
    async def go():
        primary, backup = await _stores(tmp_path)
        state = GatewayState()
        manager = _manager(backup, state)
        manager.bind_primary(primary)

        first = await manager.run(triggered_by="first")
        assert first["ok"] is True, first
        # Everything the run must report (D): id, per-table counts, pruning.
        for key in ("snapshot_at", "accounts", "schema_migrations", "tool_flags",
                    "admin_audit", "pruned", "oldest_snapshot_at", "retention_days"):
            assert key in first, key
        assert first["retention_days"] == 10 and first["accounts"] == 1
        assert first["schema_migrations"] >= 1

        snapshot = first["snapshot_at"]
        before = {
            table: await backup._fetch_all(f"SELECT * FROM {table} WHERE snapshot_at = ?", (snapshot,))
            for table in SNAPSHOT_TABLES
        }
        assert before["backup_accounts"], "the account row never reached the snapshot"

        # The primary moves on; the old snapshot must not.
        await primary.upsert_account("acct2", "ENC-A2", "ENC-C2", enabled=True)
        await primary.set_tool_flag("get_trends", True)
        await primary.delete_account("acct1")

        second = await manager.run(triggered_by="second")
        assert second["ok"] is True, second
        assert second["snapshot_at"] != snapshot
        assert second["accounts"] == 1

        after = {
            table: await backup._fetch_all(f"SELECT * FROM {table} WHERE snapshot_at = ?", (snapshot,))
            for table in SNAPSHOT_TABLES
        }
        assert after == before, "the earlier snapshot was modified by the later run"
        assert {r["label"] for r in after["backup_accounts"]} == {"acct1"}

        oldest_first = await manager.snapshot_accounts(snapshot)
        assert [r["label"] for r in oldest_first] == ["acct1"]
        newest_at, newest_rows = await manager.newest_snapshot_accounts()
        assert newest_at == second["snapshot_at"]
        assert [r["label"] for r in newest_rows] == ["acct2"]
        assert [s["snapshot_at"] for s in await manager.list_snapshots()] == [
            second["snapshot_at"], snapshot]
        await primary.close()
        await backup.close()

    asyncio.run(go())


def test_two_consecutive_runs_produce_two_distinct_snapshots(tmp_path):
    async def go():
        primary, backup = await _stores(tmp_path)
        manager = _manager(backup, GatewayState())
        manager.bind_primary(primary)
        one = await manager.run("one")
        two = await manager.run("two")
        await primary.close()
        await backup.close()
        return one, two

    one, two = asyncio.run(go())
    assert one["ok"] and two["ok"]
    assert one["snapshot_at"] != two["snapshot_at"]
    assert two["snapshot_at"] > one["snapshot_at"]  # ISO-8601 sorts chronologically


def test_legacy_mirror_tables_are_no_longer_written(tmp_path):
    """The old in-place mirror (x_accounts / tool_flags / admin_audit in the
    backup store) is left in place but unused: the snapshot tables carry the
    data now."""
    async def go():
        primary, backup = await _stores(tmp_path)
        manager = _manager(backup, GatewayState())
        manager.bind_primary(primary)
        await manager.run("one")
        await manager.run("two")
        result = (
            await backup.dump_accounts(),
            await backup.list_tool_flags(),
            await backup.dump_admin_audit(),
            len(await backup._fetch_all("SELECT * FROM backup_accounts")),
        )
        await primary.close()
        await backup.close()
        return result

    mirror_accounts, mirror_flags, mirror_audit, snapshot_rows = asyncio.run(go())
    assert mirror_accounts == [] and mirror_flags == {} and mirror_audit == []
    assert snapshot_rows == 2, "two runs must hold two account rows, one per snapshot"


def test_a_failed_run_leaves_no_partial_snapshot(tmp_path, monkeypatch):
    """The index row is written first as the run's claim; if the rows fail,
    the claim is discarded so the fallback can never pick a half snapshot."""
    async def go():
        primary, backup = await _stores(tmp_path)
        state = GatewayState()
        manager = _manager(backup, state)
        manager.bind_primary(primary)
        real_exec = backup._exec

        async def flaky(sql, params=()):
            if sql.startswith("INSERT INTO backup_admin_audit"):
                raise RuntimeError("synthetic snapshot write failure")
            return await real_exec(sql, params)

        monkeypatch.setattr(backup, "_exec", flaky)
        result = await manager.run("failing")
        leftovers = {
            table: await backup._fetch_all(f"SELECT snapshot_at FROM {table}")
            for table in ("backup_snapshots",) + SNAPSHOT_TABLES
        }
        await primary.close()
        await backup.close()
        return result, state, leftovers

    result, state, leftovers = asyncio.run(go())
    assert result["ok"] is False and result["error"]
    assert state.backup_ok is False and state.last_backup_error
    assert all(rows == [] for rows in leftovers.values()), leftovers


# ── retention ────────────────────────────────────────────────────────────

def _old_stamp(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


async def _seed_old_snapshot(backup, stamp: str) -> None:
    """An old snapshot with a row in every table (as a real run would leave)."""
    await backup._exec(
        "INSERT INTO backup_snapshots (snapshot_at, created_at, triggered_by, account_rows,"
        " migration_rows, tool_flag_rows, audit_rows) VALUES (?, ?, 'old', 1, 1, 1, 1)",
        (stamp, stamp),
    )
    await backup._exec(
        "INSERT INTO backup_accounts (snapshot_at, label, enc_auth_token, enc_ct0, enabled)"
        " VALUES (?, ?, ?, ?, 1)", (stamp, "oldacct", "ENC", "ENC"),
    )
    await backup._exec(
        "INSERT INTO backup_schema_migrations (snapshot_at, version, name, applied_at)"
        " VALUES (?, 99, 'old', ?)", (stamp, stamp),
    )
    await backup._exec(
        "INSERT INTO backup_tool_flags (snapshot_at, tool_name, enabled, updated_at)"
        " VALUES (?, 'get_trends', 1, ?)", (stamp, stamp),
    )
    await backup._exec(
        "INSERT INTO backup_admin_audit (snapshot_at, ts, action, detail, request_id)"
        " VALUES (?, ?, 'old_action', NULL, NULL)", (stamp, stamp),
    )


def test_prune_removes_only_snapshots_outside_the_window(tmp_path):
    async def go():
        primary, backup = await _stores(tmp_path)
        manager = _manager(backup, GatewayState(), retention_days=10)
        manager.bind_primary(primary)
        fresh = await manager.run("fresh")
        old = _old_stamp(11)
        await _seed_old_snapshot(backup, old)

        result = await manager.run("pruning")
        remaining = {s["snapshot_at"] for s in await manager.list_snapshots()}
        orphans = {
            table: {r["snapshot_at"] for r in
                    await backup._fetch_all(f"SELECT DISTINCT snapshot_at FROM {table}")}
            for table in SNAPSHOT_TABLES
        }
        await primary.close()
        await backup.close()
        return fresh, old, result, remaining, orphans

    fresh, old, result, remaining, orphans = asyncio.run(go())
    assert result["ok"] is True and result["pruned"] == 1, result
    assert old not in remaining, "the expired snapshot survived"
    assert fresh["snapshot_at"] in remaining, "a snapshot inside the window was pruned"
    assert result["snapshot_at"] in remaining
    assert result["oldest_snapshot_at"] == fresh["snapshot_at"]
    for table, stamps in orphans.items():
        assert old not in stamps, f"orphan rows left in {table}"
        assert stamps <= remaining, f"{table} holds rows for an unknown snapshot"


def test_retention_window_is_honoured(tmp_path):
    """A narrower window prunes what a wider one keeps."""
    async def go(days: int):
        primary, backup = await _stores(tmp_path / f"w{days}")
        manager = _manager(backup, GatewayState(), retention_days=days)
        manager.bind_primary(primary)
        await manager.run("first")
        await _seed_old_snapshot(backup, _old_stamp(3))  # older than 2, newer than 4
        result = await manager.run("second")
        remaining = {s["snapshot_at"] for s in await manager.list_snapshots()}
        await primary.close()
        await backup.close()
        return result["pruned"], len(remaining)

    assert asyncio.run(go(2)) == (1, 2)   # a 3-day-old snapshot is older than 2 days
    assert asyncio.run(go(4)) == (0, 3)   # ... but inside a 4-day window


def test_prune_failure_does_not_fail_the_run(tmp_path, monkeypatch):
    async def go():
        primary, backup = await _stores(tmp_path)
        state = GatewayState()
        manager = _manager(backup, state)
        manager.bind_primary(primary)
        await manager.run("first")
        await _seed_old_snapshot(backup, _old_stamp(30))

        async def exploding_delete(snapshot_at: str) -> None:
            raise RuntimeError("synthetic prune failure")

        monkeypatch.setattr(manager, "_delete_snapshot_rows", exploding_delete)
        result = await manager.run("pruning")
        # the backup itself is intact and still recorded as a success
        latest = await manager.latest_snapshot()
        rows = await backup._fetch_all("SELECT * FROM backup_accounts WHERE snapshot_at = ?",
                                       (result["snapshot_at"],))
        await primary.close()
        await backup.close()
        return result, state, latest, rows

    result, state, latest, rows = asyncio.run(go())
    assert result["ok"] is True, result
    assert result["pruned"] == 0 and "prune_error" in result
    assert state.backup_ok is True and state.last_backup_error is None
    assert latest == result["snapshot_at"] and rows, "the snapshot must survive a failed prune"


# ── fallback: store level ────────────────────────────────────────────────

def test_empty_primary_hydrates_the_pool_from_the_newest_snapshot(tmp_path):
    async def go():
        crypto = _crypto()
        primary = AccountStore(_url(tmp_path, "primary.db"))
        backup = AccountStore(_url(tmp_path, "backup.db"))
        for store in (primary, backup):
            await store.connect()
            await store.init_schema()
        for label in ("acct1", "acct2"):
            await primary.upsert_account(label, crypto.encrypt(f"tok-{label}"),
                                         crypto.encrypt(f"ct0-{label}"), enabled=True)
        state = GatewayState()
        manager = _manager(backup, state)
        manager.bind_primary(primary)
        snapshot = await manager.run("seed")
        # All accounts are gone from the reachable primary store.
        for label in ("acct1", "acct2"):
            await primary.delete_account(label)

        adapter = _FakeAdapter()
        monitor = _monitor(primary, crypto, adapter, state, manager)
        results = await monitor.check_once(source="startup")
        stored = await primary.get_all_accounts()
        await primary.close()
        await backup.close()
        return snapshot, state, results, adapter, stored

    snapshot, state, results, adapter, stored = asyncio.run(go())
    assert results == {"acct1": XStatus.CONNECTED.value, "acct2": XStatus.CONNECTED.value}
    assert sorted(adapter.synced) == [
        ("acct1", "tok-acct1", "ct0-acct1"), ("acct2", "tok-acct2", "ct0-acct2")]
    assert state.restored_from_snapshot == snapshot["snapshot_at"]
    assert state.accounts_configured == 2 and state.accounts_enabled == 2
    assert stored == [], "the automatic fallback must never write the primary store"


def test_no_snapshot_means_no_fallback(tmp_path):
    async def go():
        crypto = _crypto()
        primary = AccountStore(_url(tmp_path, "primary.db"))
        backup = AccountStore(_url(tmp_path, "backup.db"))
        for store in (primary, backup):
            await store.connect()
            await store.init_schema()
        state = GatewayState()
        manager = _manager(backup, state)
        manager.bind_primary(primary)
        adapter = _FakeAdapter()
        monitor = _monitor(primary, crypto, adapter, state, manager)
        results = await monitor.check_once(source="startup")
        await primary.close()
        await backup.close()
        return state, results, adapter

    state, results, adapter = asyncio.run(go())
    assert results == {} and adapter.synced == []
    assert state.restored_from_snapshot is None
    assert state.x_status is XStatus.NOT_CONFIGURED


def test_unreadable_primary_without_a_snapshot_reports_config_error(tmp_path, monkeypatch):
    """Nothing to serve and nothing to fall back to: the status must say so
    instead of pretending the gateway is simply unconfigured."""
    async def go():
        crypto = _crypto()
        primary = AccountStore(_url(tmp_path, "primary.db"))
        backup = AccountStore(_url(tmp_path, "backup.db"))
        for store in (primary, backup):
            await store.connect()
            await store.init_schema()
        state = GatewayState()
        manager = _manager(backup, state)          # backup store, no snapshot
        manager.bind_primary(primary)

        async def unreachable(*args, **kwargs):
            raise RuntimeError("primary store is down")

        monkeypatch.setattr(primary, "get_all_accounts", unreachable)
        adapter = _FakeAdapter()
        monitor = _monitor(primary, crypto, adapter, state, manager)
        results = await monitor.check_once(source="startup")
        await primary.close()
        await backup.close()
        return state, results

    state, results = asyncio.run(go())
    assert results == {}
    assert state.x_status is XStatus.CONFIG_ERROR
    assert "store unreadable" in (state.last_error or "")
    assert state.restored_from_snapshot is None


def test_unreachable_primary_falls_back_to_the_snapshot(tmp_path, monkeypatch):
    """A store that cannot be read at all is the other half of the rule."""
    async def go():
        crypto = _crypto()
        primary = AccountStore(_url(tmp_path, "primary.db"))
        backup = AccountStore(_url(tmp_path, "backup.db"))
        for store in (primary, backup):
            await store.connect()
            await store.init_schema()
        await primary.upsert_account("acct1", crypto.encrypt("tok"), crypto.encrypt("ct0"))
        state = GatewayState()
        manager = _manager(backup, state)
        manager.bind_primary(primary)
        snapshot = await manager.run("seed")

        async def unreachable(*args, **kwargs):
            raise RuntimeError("primary store is down")

        monkeypatch.setattr(primary, "get_all_accounts", unreachable)
        adapter = _FakeAdapter()
        monitor = _monitor(primary, crypto, adapter, state, manager)
        results = await monitor.check_once(source="startup")
        await primary.close()
        await backup.close()
        return snapshot, state, results, adapter

    snapshot, state, results, adapter = asyncio.run(go())
    assert results == {"acct1": XStatus.CONNECTED.value}
    assert adapter.synced == [("acct1", "tok", "ct0")]
    assert state.restored_from_snapshot == snapshot["snapshot_at"]


def test_disabled_accounts_are_not_resurrected_from_a_snapshot(tmp_path):
    """Every account disabled is an operator decision, not an outage: the
    primary stays authoritative and nothing is hydrated from the snapshot."""
    async def go():
        crypto = _crypto()
        primary = AccountStore(_url(tmp_path, "primary.db"))
        backup = AccountStore(_url(tmp_path, "backup.db"))
        for store in (primary, backup):
            await store.connect()
            await store.init_schema()
        await primary.upsert_account("acct1", crypto.encrypt("tok"), crypto.encrypt("ct0"))
        state = GatewayState()
        manager = _manager(backup, state)
        manager.bind_primary(primary)
        await manager.run("seed")
        await primary.set_account_enabled("acct1", False)

        adapter = _FakeAdapter()
        monitor = _monitor(primary, crypto, adapter, state, manager)
        results = await monitor.check_once(source="startup")
        await primary.close()
        await backup.close()
        return state, results, adapter

    state, results, adapter = asyncio.run(go())
    assert results == {} and adapter.synced == []
    assert state.restored_from_snapshot is None


# ── fallback: one corrupt row ────────────────────────────────────────────

def test_corrupt_row_falls_back_to_its_newest_snapshot_row(tmp_path):
    async def go():
        crypto = _crypto()
        primary = AccountStore(_url(tmp_path, "primary.db"))
        backup = AccountStore(_url(tmp_path, "backup.db"))
        for store in (primary, backup):
            await store.connect()
            await store.init_schema()
        await primary.upsert_account("acct1", crypto.encrypt("GOOD-TOKEN"),
                                    crypto.encrypt("GOOD-CT0"), enabled=True)
        state = GatewayState()
        manager = _manager(backup, state)
        manager.bind_primary(primary)
        snapshot = await manager.run("seed")
        # The stored row becomes undecryptable (wrong key / truncated value).
        await primary._exec("UPDATE x_accounts SET enc_auth_token = 'not-a-fernet-token'"
                            " WHERE label = 'acct1'")
        adapter = _FakeAdapter()
        monitor = _monitor(primary, crypto, adapter, state, manager)
        results = await monitor.check_once(source="startup")
        row = await primary._fetch_one("SELECT enc_auth_token, status FROM x_accounts"
                                       " WHERE label = 'acct1'")
        await primary.close()
        await backup.close()
        return snapshot, state, results, adapter, row

    snapshot, state, results, adapter, row = asyncio.run(go())
    assert results == {"acct1": XStatus.CONNECTED.value}
    assert adapter.synced == [("acct1", "GOOD-TOKEN", "GOOD-CT0")]
    assert state.restored_from_snapshot == snapshot["snapshot_at"]
    assert state.restored_labels == ["acct1"]
    # The corrupt row stays corrupt: repairing it is an explicit restore.
    assert row["enc_auth_token"] == "not-a-fernet-token"


def test_corrupt_row_without_a_snapshot_still_reports_config_error(tmp_path):
    async def go():
        crypto = _crypto()
        primary = AccountStore(_url(tmp_path, "primary.db"))
        backup = AccountStore(_url(tmp_path, "backup.db"))
        for store in (primary, backup):
            await store.connect()
            await store.init_schema()
        await primary.upsert_account("acct1", "not-a-fernet-token", "junk", enabled=True)
        state = GatewayState()
        manager = _manager(backup, state)          # no snapshot was ever taken
        manager.bind_primary(primary)
        adapter = _FakeAdapter()
        monitor = _monitor(primary, crypto, adapter, state, manager)
        results = await monitor.check_once(source="startup")
        row = await primary._fetch_one("SELECT status FROM x_accounts WHERE label = 'acct1'")
        await primary.close()
        await backup.close()
        return state, results, adapter, row

    state, results, adapter, row = asyncio.run(go())
    assert results == {"acct1": XStatus.CONFIG_ERROR.value}
    assert adapter.synced == [] and state.restored_from_snapshot is None
    assert row["status"] == XStatus.CONFIG_ERROR.value


def test_expired_session_is_never_papered_over_with_snapshot_cookies(tmp_path, monkeypatch):
    """Validation saying "expired" is a real outage. The snapshot is not a
    time machine: the CURRENT credential must be the only one considered."""
    async def go():
        crypto = _crypto()
        primary = AccountStore(_url(tmp_path, "primary.db"))
        backup = AccountStore(_url(tmp_path, "backup.db"))
        for store in (primary, backup):
            await store.connect()
            await store.init_schema()
        await primary.upsert_account("acct1", crypto.encrypt("OLD-TOKEN"),
                                    crypto.encrypt("OLD-CT0"), enabled=True)
        state = GatewayState()
        manager = _manager(backup, state)
        manager.bind_primary(primary)
        await manager.run("seed")          # snapshot holds OLD-TOKEN
        await primary.upsert_account("acct1", crypto.encrypt("NEW-TOKEN"),
                                     crypto.encrypt("NEW-CT0"), enabled=True)

        adapter = _FakeAdapter(status=XStatus.INVALID_SESSION)
        monitor = _monitor(primary, crypto, adapter, state, manager)
        consulted: list[str] = []
        original = monitor._decrypt_snapshot_credential

        async def spy(label):
            consulted.append(label)
            return await original(label)

        monkeypatch.setattr(monitor, "_decrypt_snapshot_credential", spy)
        results = await monitor.check_once(source="background")
        await primary.close()
        await backup.close()
        return state, results, adapter, consulted

    state, results, adapter, consulted = asyncio.run(go())
    assert results == {"acct1": XStatus.INVALID_SESSION.value}
    assert adapter.synced == [("acct1", "NEW-TOKEN", "NEW-CT0")]
    assert consulted == [], "the snapshot must not be consulted on an expired session"
    assert state.restored_from_snapshot is None and state.restored_labels == []


# ── explicit restore route ───────────────────────────────────────────────

def _app_with_backup(tmp_path, **overrides):
    from app.main import create_app

    settings = Settings(
        MCP_ACCESS_TOKEN="m" * 48,
        ADMIN_TOKEN="a" * 48,
        CREDENTIAL_ENCRYPTION_KEY=Fernet.generate_key().decode(),
        DATABASE_URL=_url(tmp_path, "primary.db"),
        BACKUP_DATABASE_URL=_url(tmp_path, "backup.db"),
        SPECTRE_DB_PATH=str(tmp_path / "spectre.db"),
        VALIDATE_ON_STARTUP=False,
        SESSION_CHECK_INTERVAL_SECONDS=3600,
        LOG_LEVEL="WARNING",
        **overrides,
    )
    return create_app(settings)


def test_restore_route_rejects_anonymous_and_cross_site_callers(client):
    client.cookies.clear()
    assert client.post("/admin/api/backup/restore").status_code == 401
    assert client.post("/admin/api/backup/restore",
                       headers=MCP).status_code == 401
    # Bearer admin (a script) is exempt from the CSRF header, but this app has
    # no backup store configured, so it answers 503 rather than restoring.
    assert client.post("/admin/api/backup/restore", headers=ADMIN).status_code == 503


def test_restore_route_requires_the_csrf_header_for_cookie_callers(tmp_path):
    app = _app_with_backup(tmp_path)
    bearer = {"Authorization": f"Bearer {'a' * 48}"}
    with TestClient(app) as client:
        # a snapshot exists, so the only thing standing between the cookie
        # caller and a restore is the CSRF guard
        client.post("/admin/api/accounts", headers=bearer, json={
            "label": "csrfprobe", "auth_token": "t" * 40, "ct0": "c" * 160, "enabled": False})
        assert client.post("/admin/api/backup", headers=bearer).json()["ok"] is True
        assert client.post("/admin/api/login", json={"token": "a" * 48}).status_code == 200
        blocked = client.post("/admin/api/backup/restore")
        assert blocked.status_code == 403, blocked.text
        allowed = client.post("/admin/api/backup/restore",
                              headers={"X-Requested-With": "XMLHttpRequest"})
        assert allowed.status_code == 200, allowed.text
        assert allowed.json()["ok"] is True


def test_restore_route_restores_the_newest_snapshot_by_default(tmp_path):
    app = _app_with_backup(tmp_path)
    admin = {"Authorization": f"Bearer {'a' * 48}"}
    with TestClient(app) as client:
        created = client.post("/admin/api/accounts", headers=admin, json={
            "label": "restored1", "auth_token": "t" * 40, "ct0": "c" * 160,
            "enabled": False})
        assert created.status_code == 200, created.text
        run = client.post("/admin/api/backup", headers=admin).json()
        assert run["ok"] is True, run
        snapshot = run["snapshot_at"]
        assert client.delete("/admin/api/accounts/restored1", headers=admin).status_code == 200
        assert client.get("/admin/api/accounts", headers=admin).json()["accounts"] == []

        restored = client.post("/admin/api/backup/restore", headers=admin)
        assert restored.status_code == 200, restored.text
        body = restored.json()
        assert body["ok"] is True and body["snapshot_at"] == snapshot
        assert body["accounts"] == 1
        labels = [a["label"] for a in client.get("/admin/api/accounts", headers=admin)
                  .json()["accounts"]]
        assert labels == ["restored1"], "the deleted account was not resurrected"
        assert body["pool_hydrated"] is True

        overview = client.get("/admin/api/overview", headers=admin).json()
        assert [s["snapshot_at"] for s in overview["backup"]["snapshots"]] == [snapshot]


def test_restore_route_accepts_an_explicit_snapshot_and_404s_on_unknown(tmp_path):
    app = _app_with_backup(tmp_path)
    admin = {"Authorization": f"Bearer {'a' * 48}"}
    with TestClient(app) as client:
        assert client.post("/admin/api/accounts", headers=admin, json={
            "label": "first", "auth_token": "t" * 40, "ct0": "c" * 160,
            "enabled": False}).status_code == 200
        older = client.post("/admin/api/backup", headers=admin).json()["snapshot_at"]
        assert client.post("/admin/api/accounts", headers=admin, json={
            "label": "second", "auth_token": "u" * 40, "ct0": "d" * 160,
            "enabled": False}).status_code == 200
        newest = client.post("/admin/api/backup", headers=admin).json()["snapshot_at"]
        assert newest != older

        # restoring the OLDER snapshot must not resurrect the newer account
        assert client.delete("/admin/api/accounts/first", headers=admin).status_code == 200
        assert client.delete("/admin/api/accounts/second", headers=admin).status_code == 200
        body = client.post("/admin/api/backup/restore", headers=admin,
                           json={"snapshot_at": older}).json()
        assert body["ok"] is True and body["snapshot_at"] == older
        labels = [a["label"] for a in client.get("/admin/api/accounts", headers=admin)
                  .json()["accounts"]]
        assert labels == ["first"]

        missing = client.post("/admin/api/backup/restore", headers=admin,
                              json={"snapshot_at": "1999-01-01T00:00:00.000000+00:00"})
        assert missing.status_code == 404


def test_restore_route_audits_the_action(tmp_path):
    app = _app_with_backup(tmp_path)
    admin = {"Authorization": f"Bearer {'a' * 48}"}
    with TestClient(app) as client:
        client.post("/admin/api/accounts", headers=admin, json={
            "label": "audited", "auth_token": "t" * 40, "ct0": "c" * 160, "enabled": False})
        client.post("/admin/api/backup", headers=admin)
        client.post("/admin/api/backup/restore", headers=admin)
        rows = client.get("/admin/api/audit", headers=admin).json()["rows"]
        entry = next(r for r in rows if r["action"] == "backup_restore")
        assert "accounts=" in entry["detail"]
        assert "a" * 48 not in entry["detail"]


# ── configuration ────────────────────────────────────────────────────────

def test_retention_setting_is_read_from_config_and_documented(tmp_path):
    assert Settings().BACKUP_RETENTION_DAYS == 10, "the documented default changed"
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "BACKUP_RETENTION_DAYS=10" in env_example

    app = _app_with_backup(tmp_path, BACKUP_RETENTION_DAYS=3)
    mcp = {"Authorization": f"Bearer {'m' * 48}"}
    with TestClient(app) as client:
        assert client.app.state.backup_manager.retention_days == 3
        body = client.get("/diagnostics", headers=mcp).json()
        assert body["backup"]["retention_days"] == 3
        assert body["x_session"]["restored_from_snapshot"] is None
        status = client.get("/status").json()
        assert status["restored_from_snapshot"] is None


def test_admin_delete_snapshot_route(tmp_path):
    app = _app_with_backup(tmp_path)
    admin = {"Authorization": f"Bearer {'a' * 48}"}
    with TestClient(app) as client:
        # 1. Trigger a backup
        r = client.post("/admin/api/backup", headers=admin)
        assert r.status_code == 200
        overview = client.get("/admin/api/overview", headers=admin).json()
        snapshots = overview["backup"]["snapshots"]
        assert len(snapshots) >= 1
        snapshot_at = snapshots[0]["snapshot_at"]

        # 2. Delete the snapshot
        del_resp = client.delete(f"/admin/api/backup/snapshots/{snapshot_at}", headers=admin)
        assert del_resp.status_code == 200
        assert del_resp.json() == {"deleted": snapshot_at}

        # 3. Verify it is gone
        overview2 = client.get("/admin/api/overview", headers=admin).json()
        remaining = [s["snapshot_at"] for s in overview2["backup"]["snapshots"]]
        assert snapshot_at not in remaining

        # 4. Deleting non-existent snapshot returns 404
        del_again = client.delete(f"/admin/api/backup/snapshots/{snapshot_at}", headers=admin)
        assert del_again.status_code == 404
