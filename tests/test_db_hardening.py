"""Regression tests for the DB-layer audit findings (B1-B4).

B1 sqlite connections are closed deterministically (the sqlite3 context
   manager commits but never closes).
B2 migration claiming is atomic across concurrent starters.
B3 statement splitting is quote-aware and refuses parameterized
   multi-statement SQL instead of binding the same params everywhere.
B4 the postgres `?` -> `$n` rewrite ignores literals/identifiers.
B6 migrations are portable: the claim is the schema_migrations primary key,
   not a vendor advisory lock (CockroachDB has no pg_advisory_lock).
"""

from __future__ import annotations

import asyncio
import sqlite3

import pytest

from app import db as db_module
from app.backup import BackupManager
from app.db import AccountStore
from app.models import GatewayState


def _tmp_url(tmp_path, name="t.db") -> str:
    return f"sqlite:///{tmp_path / name}"


# ── B1: no connection leak ───────────────────────────────────────────────

def test_sqlite_connections_are_closed(tmp_path, monkeypatch):
    store = AccountStore(_tmp_url(tmp_path))
    opened: list[sqlite3.Connection] = []
    original = AccountStore._sqlite_connect

    def recording_connect(self):
        conn = original(self)
        opened.append(conn)
        return conn

    monkeypatch.setattr(AccountStore, "_sqlite_connect", recording_connect)

    async def go():
        await store.connect()
        await store.init_schema()
        await store.set_meta("k", "v")
        assert await store.get_meta("k") == "v"
        await store.log_tool_usage("get_trends", True, None, 1, None)
        assert await store.list_tool_usage(limit=1)

    asyncio.run(go())

    assert opened, "expected the sqlite path to open connections"
    for conn in opened:
        # A closed sqlite3.Connection refuses further use; an open one does not.
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")


# ── B2: atomic migration claiming ────────────────────────────────────────

_SLOW_SEED = (
    "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 100000) "
    "INSERT INTO meta (k, v, updated_at) SELECT 'seed-' || x, 'v', 't' FROM c"
)

_ALTER = "ALTER TABLE x_accounts ADD COLUMN probe_col TEXT"


def test_concurrent_init_schema_applies_migrations_once(tmp_path, monkeypatch):
    """Two instances booting at once must not both run non-idempotent DDL.

    The fake migration set contains a deliberately slow statement followed by
    a non-idempotent ALTER: without an atomic claim both runners read the same
    applied set and the loser re-runs the ALTER (duplicate column error)."""
    real_migrations = db_module._migrations_for

    def fake_migrations(backend):
        return list(real_migrations(backend)) + [
            (101, "slow_seed", [_SLOW_SEED]),
            (102, "non_idempotent_alter", [_ALTER]),
        ]

    monkeypatch.setattr(db_module, "_migrations_for", fake_migrations)

    url = _tmp_url(tmp_path)
    first, second = AccountStore(url, label="one"), AccountStore(url, label="two")

    async def go():
        await first.connect()
        await second.connect()
        # Overlap the runners: the second starts while the first is mid-DDL.
        await asyncio.gather(first.init_schema(), _after(0.05, second.init_schema()))

    async def _after(delay: float, coro):
        await asyncio.sleep(delay)
        return await coro

    asyncio.run(go())

    conn = sqlite3.connect(str(tmp_path / "t.db"))
    try:
        versions = [r[0] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
        assert versions == sorted(set(versions)), "a migration was applied twice"
        assert 101 in versions and 102 in versions
        cols = [r[1] for r in conn.execute("PRAGMA table_info(x_accounts)")]
        assert cols.count("probe_col") == 1
        seeds = conn.execute("SELECT COUNT(*) FROM meta WHERE k LIKE 'seed-%'").fetchone()[0]
        assert seeds == 100000, "the seed statement ran more than once"
    finally:
        conn.close()


# ── B3: quote-aware splitting + parameter guard ───────────────────────────

def test_split_statements_ignores_semicolons_in_literals():
    store = AccountStore("sqlite:///unused.db")
    assert store._split_statements("SELECT ';' AS s; SELECT 2") == [
        "SELECT ';' AS s", "SELECT 2"]
    assert store._split_statements("SELECT 'a;b' AS s") == ["SELECT 'a;b' AS s"]
    assert store._split_statements('SELECT ";" AS s') == ['SELECT ";" AS s']
    # Trailing/duplicate separators produce no empty statements.
    assert store._split_statements("SELECT 1;;") == ["SELECT 1"]


def test_parameterized_multi_statement_refused():
    store = AccountStore("sqlite:///unused.db")
    with pytest.raises(ValueError, match="single statement"):
        store._split_statements("UPDATE a SET b = ?; UPDATE c SET d = ?", (1, 2))
    # Single statement with params stays fine.
    assert store._split_statements("UPDATE a SET b = ?", (1,)) == ["UPDATE a SET b = ?"]


async def test_exec_refuses_parameterized_multi_statement(tmp_path):
    store = AccountStore(_tmp_url(tmp_path))
    await store.connect()
    await store.init_schema()
    with pytest.raises(ValueError, match="single statement"):
        await store._exec("UPDATE meta SET v = ?; UPDATE meta SET v = ?", ("a", "b"))
    await store.close()


def test_unterminated_literal_refused():
    store = AccountStore("sqlite:///unused.db")
    with pytest.raises(ValueError, match="unterminated"):
        store._split_statements("SELECT 'oops")
    with pytest.raises(ValueError, match="unterminated"):
        AccountStore._pg("SELECT 'oops ?")


# ── B4: quote-aware postgres placeholder rewrite ──────────────────────────

def test_pg_rewrite_ignores_question_marks_in_literals_and_identifiers():
    pg = AccountStore._pg
    assert pg("SELECT '?' AS q, ? AS a FROM t WHERE b = ?") == \
        "SELECT '?' AS q, $1 AS a FROM t WHERE b = $2"
    assert pg('SELECT "?" FROM t WHERE x = ?') == 'SELECT "?" FROM t WHERE x = $1'
    assert pg("SELECT 1 -- why?\nWHERE x = ?") == "SELECT 1 -- why?\nWHERE x = $1"
    assert pg("SELECT /* ? */ ?") == "SELECT /* ? */ $1"
    # Doubled quotes inside a literal are data, not terminators.
    assert pg("SELECT 'it''s ?' , ?") == "SELECT 'it''s ?' , $1"
    # (An unterminated literal is refused — see test_unterminated_literal_refused.)


# ── B5: backslash escaping follows the backend's dialect ────────────────

def test_standard_sql_literal_may_end_in_a_backslash():
    """Postgres/sqlite are standard SQL: backslash is an ordinary character,
    so `'C:\\'` is a complete literal (it used to raise 'unterminated')."""
    sqlite = AccountStore("sqlite:///unused.db")
    assert sqlite._split_statements("SELECT 'C:\\' AS x; SELECT 2") == \
        ["SELECT 'C:\\' AS x", "SELECT 2"]
    assert AccountStore._pg("SELECT 'C:\\' AS x, ?") == "SELECT 'C:\\' AS x, $1"
    # A doubled backslash is just two characters, never an escape.
    assert AccountStore._pg("SELECT 'a\\\\' AS x, ?") == "SELECT 'a\\\\' AS x, $1"


def test_mysql_keeps_backslash_escaping():
    """MySQL really does escape with a backslash, so the scanner must still
    treat `'C:\\'` there as an unterminated literal."""
    mysql = AccountStore("mysql://user:pass@localhost:3306/db")
    with pytest.raises(ValueError, match="unterminated string literal"):
        mysql._split_statements("SELECT 'C:\\' AS x")
    # An escaped backslash (two chars) then the terminator is valid MySQL.
    assert mysql._split_statements("SELECT 'C:\\\\' AS x") == ["SELECT 'C:\\\\' AS x"]
    # ... and the escaped quote stays inside the literal in both dialects.
    assert mysql._split_statements("SELECT 'it\\'s' AS s") == ["SELECT 'it\\'s' AS s"]


def test_genuinely_unterminated_input_is_still_refused_in_both_dialects():
    for url in ("sqlite:///unused.db", "mysql://user:pass@localhost:3306/db"):
        store = AccountStore(url)
        with pytest.raises(ValueError, match="unterminated string literal"):
            store._split_statements("SELECT 'oops")
        with pytest.raises(ValueError, match="unterminated block comment"):
            store._split_statements("SELECT 1 /* oops")
        with pytest.raises(ValueError, match="unterminated string literal"):
            store._split_statements('SELECT "oops')
        # A closing backslash never becomes an escape hatch for the scanner:
        # the dialect decides, not the presence of the character.
        assert store._split_statements("SELECT 'closed' AS x") == ["SELECT 'closed' AS x"]


# ── B6: the migration runner is portable (no pg_advisory_lock) ───────────
#
# Reported in production: the backup store — a CockroachDB database — failed
# to initialise with
#     startup: backup store unavailable: unknown function: pg_advisory_lock()
# so BackupManager was never built and scheduled backups silently never ran.
#
# The stub below is CockroachDB-shaped for exactly the properties that
# matter: it raises on pg_advisory_lock (as an unknown function does), and it
# enforces the schema_migrations PRIMARY KEY on INSERT ... ON CONFLICT
# DO NOTHING, which is the portable arbiter the runner now relies on.

_CLAIM_INSERT = "INSERT INTO schema_migrations"
_CLAIM_UPDATE = "UPDATE schema_migrations SET name = $2, applied_at"
_CLAIM_DELETE = "DELETE FROM schema_migrations"
_CLAIM_TAKEOVER = "UPDATE schema_migrations SET name = $2 WHERE"


class _ClaimRows(dict):
    """schema_migrations rows with PRIMARY KEY semantics: a conflicting
    INSERT inserts nothing, and an UPDATE/DELETE only touches the row whose
    claim token still matches. Mapped as {version: (name, applied_at)}."""

    def insert(self, version, claim) -> None:
        self.setdefault(version, (claim, None))  # a conflict is a no-op

    def read(self, version):
        return self.get(version)

    def settle(self, version, claim, name, applied_at) -> None:
        if self.get(version) == (claim, None):
            self[version] = (name, applied_at)

    def release(self, version, claim) -> None:
        if self.get(version) == (claim, None):
            del self[version]

    def take_over(self, version, stale, claim) -> None:
        if self.get(version) == (stale, None):
            self[version] = (claim, None)

    @property
    def applied(self) -> set[int]:
        return {v for v, (_, at) in self.items() if at is not None}


class _CockroachLikeConn:
    """Stands in for an asyncpg connection to an engine without advisory
    locks (CockroachDB raises 'unknown function: pg_advisory_lock()' — here
    from BOTH execute and fetch, as the reported failure did)."""

    def __init__(self, slow_ddl_seconds: float = 0.0):
        self.statements: list[str] = []          # every SQL string it received
        self.ddl: list[str] = []                 # DDL it actually ran
        self.claims = _ClaimRows()
        self.slow_ddl_seconds = slow_ddl_seconds

    def _no_advisory_locks(self, sql: str) -> None:
        if "advisory" in sql:
            raise RuntimeError(f"unknown function: {sql.strip()}")

    async def execute(self, sql, *args):
        self._no_advisory_locks(sql)
        self.statements.append(sql)
        if sql.startswith(_CLAIM_INSERT):
            self.claims.insert(args[0], args[1])
            return
        if sql.startswith(_CLAIM_UPDATE):
            self.claims.settle(args[0], args[3], args[1], args[2])
            return
        if sql.startswith(_CLAIM_DELETE):
            self.claims.release(args[0], args[1])
            return
        if sql.startswith(_CLAIM_TAKEOVER):
            self.claims.take_over(args[0], args[2], args[1])
            return
        if self.slow_ddl_seconds:
            await asyncio.sleep(self.slow_ddl_seconds)
        self.ddl.append(sql)

    async def fetch(self, sql, *args):
        self._no_advisory_locks(sql)
        self.statements.append(sql)
        return []

    async def fetchrow(self, sql, *args):
        self._no_advisory_locks(sql)
        self.statements.append(sql)
        if "FROM schema_migrations" in sql:
            row = self.claims.read(args[0])
            return None if row is None else {"name": row[0], "applied_at": row[1]}
        return None


class _MySqlLikeCursor:
    """aiomysql-shaped cursor modelling the same claim protocol, so the
    MySQL dialect of the runner (``%s`` placeholders, ON DUPLICATE KEY as
    the no-op-on-conflict form) is exercised too."""

    def __init__(self, conn):
        self._conn = conn
        self._row = None

    async def execute(self, sql, args=None):
        self._conn.statements.append((sql, tuple(args or ())))
        if "?" in sql:
            raise AssertionError(f"mysql must not see qmark placeholders: {sql}")
        if "LOCK(" in sql:
            raise RuntimeError(f"MySQL GET_LOCK is not part of the portable path: {sql}")
        rows = self._conn.claims
        if sql.startswith("INSERT INTO schema_migrations"):
            rows.insert(args[0], args[1])
        elif sql.startswith("SELECT name, applied_at FROM schema_migrations"):
            self._row = rows.read(args[0])
        elif sql.startswith("UPDATE schema_migrations SET name = %s, applied_at"):
            rows.settle(args[2], args[3], args[0], args[1])
        elif sql.startswith("DELETE FROM schema_migrations"):
            rows.release(args[0], args[1])
        elif sql.startswith("UPDATE schema_migrations SET name = %s WHERE"):
            rows.take_over(args[1], args[2], args[0])
        else:
            self._conn.ddl.append(sql)

    async def fetchone(self):
        return self._row

    async def fetchall(self):
        return [self._row] if self._row is not None else []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _MySqlLikeConn:
    def __init__(self):
        self.statements: list[tuple[str, tuple]] = []
        self.ddl: list[str] = []
        self.claims = _ClaimRows()

    def cursor(self, *args):
        return _MySqlLikeCursor(self)


class _StubAcquire:
    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, *exc):
        return False


class _StubPool:
    def __init__(self, conn):
        self._conn = conn

    def acquire(self):
        return _StubAcquire(self._conn)

    async def close(self):
        pass

    async def wait_closed(self):
        pass


def _crdb_backed_store(conn: _CockroachLikeConn | None = None):
    """A postgres-flavoured store whose driver is the CockroachDB-shaped stub.
    Pass an existing conn to model two instances pointed at one database."""
    store = AccountStore(
        "postgresql://user:pass@free-tier.cockroachlabs.cloud:26257/defaultdb?sslmode=verify-full"
    )
    conn = conn or _CockroachLikeConn()
    store._pg_pool = _StubPool(conn)
    return store, conn


def _tidb_backed_store() -> tuple[AccountStore, _MySqlLikeConn]:
    store = AccountStore("mysql://user:pass@tidb.example:4000/kxstrel")
    conn = _MySqlLikeConn()
    store._my_pool = _StubPool(conn)
    return store, conn


def test_mysql_initialisation_uses_the_same_claim_and_no_get_lock():
    """MySQL takes the identical portable path: claims by primary key, no
    GET_LOCK, no qmark placeholders reaching the driver."""
    store, conn = _tidb_backed_store()

    asyncio.run(store.init_schema())

    assert conn.claims.applied == {v for v, _, _ in db_module._migrations_for("mysql")}
    assert "CREATE TABLE IF NOT EXISTS x_accounts" in "\n".join(conn.ddl)
    inserts = [s for s, _ in conn.statements if s.startswith("INSERT INTO schema_migrations")]
    assert inserts and all("ON DUPLICATE KEY UPDATE" in s for s in inserts)



def test_concurrent_initialisation_applies_each_migration_once(monkeypatch):
    """Two instances booting at once on a lockless engine: the loser of each
    claim waits for the winner and then skips, so no DDL runs twice."""
    monkeypatch.setattr(db_module, "_MIGRATION_CLAIM_POLL_SECONDS", 0.01)
    conn = _CockroachLikeConn(slow_ddl_seconds=0.02)
    first, _ = _crdb_backed_store(conn)
    second, _ = _crdb_backed_store(conn)

    async def go():
        await asyncio.gather(first.init_schema(), second.init_schema())

    asyncio.run(go())

    ddl = "\n".join(conn.ddl)
    for table in ("x_accounts", "tool_flags", "tool_usage", "admin_audit", "meta"):
        assert ddl.count(f"CREATE TABLE IF NOT EXISTS {table}") == 1, table
    applied = sorted(v for v, (_, at) in conn.claims.items() if at is not None)
    assert applied == sorted(v for v, _, _ in db_module._migrations_for("postgres"))


def test_init_schema_survives_a_backend_without_advisory_locks():
    """init_schema() must apply every migration and return normally on an
    engine that has no pg_advisory_lock — it used to raise instead, which is
    what left the backup store uninitialised."""
    store, conn = _crdb_backed_store()

    asyncio.run(store.init_schema())          # must not raise

    applied = {v for v, (_, at) in conn.claims.items() if at is not None}
    expected = {v for v, _, _ in db_module._migrations_for("postgres")}
    assert applied == expected, f"migrations missing: {sorted(expected - applied)}"
    ddl = "\n".join(conn.ddl)
    for table in ("x_accounts", "tool_flags", "tool_usage", "admin_audit", "meta"):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in ddl
    assert not any("advisory" in s for s in conn.statements if "schema_migrations" not in s)


def test_second_initialisation_does_not_rerun_applied_migrations():
    """The loser of the claim (primary-key conflict) must skip the DDL
    entirely, not re-run it and not mark the version applied twice."""
    store, conn = _crdb_backed_store()
    asyncio.run(store.init_schema())
    first_run = list(conn.ddl)

    asyncio.run(store.init_schema())          # second instance / restart

    # Only ensure_table() re-issues its IF NOT EXISTS guard; no version's DDL
    # runs a second time.
    second_run = conn.ddl[len(first_run):]
    assert all("schema_migrations" in s for s in second_run), second_run
    assert len(first_run) > 1, "the first run should have applied migrations"
    applied = {v for v, (_, at) in conn.claims.items() if at is not None}
    assert applied == {v for v, _, _ in db_module._migrations_for("postgres")}


def test_abandoned_claim_is_taken_over_and_the_version_is_retried(monkeypatch):
    """A claim row left behind by a process that died mid-DDL must not wedge
    startup: after the wait the runner takes the claim over and re-runs the
    (idempotent) DDL, instead of leaving the version permanently unapplied."""
    monkeypatch.setattr(db_module, "_MIGRATION_CLAIM_WAIT_SECONDS", 0.05)
    monkeypatch.setattr(db_module, "_MIGRATION_CLAIM_POLL_SECONDS", 0.01)
    store, conn = _crdb_backed_store()
    conn.claims[1] = ("x_accounts#claim-deadbeef", None)   # owner never settled

    asyncio.run(store.init_schema())

    assert conn.claims[1][1] is not None, "the abandoned version was never settled"
    assert "CREATE TABLE IF NOT EXISTS x_accounts" in "\n".join(conn.ddl)


def test_failed_ddl_leaves_the_version_unapplied(monkeypatch):
    """A migration that raises must not end up recorded as applied: the claim
    is dropped so the next boot retries the whole version."""
    store, conn = _crdb_backed_store()
    real_execute = _CockroachLikeConn.execute

    async def exploding_execute(self, sql, *args):
        if "CREATE TABLE IF NOT EXISTS tool_usage" in sql:
            raise RuntimeError("synthetic DDL failure")
        return await real_execute(self, sql, *args)

    monkeypatch.setattr(_CockroachLikeConn, "execute", exploding_execute)
    with pytest.raises(RuntimeError, match="synthetic DDL failure"):
        asyncio.run(store.init_schema())

    settled = {v for v, (_, at) in conn.claims.items() if at is not None}
    assert settled == {1, 2}, "only the versions that completed may be applied"
    assert 3 not in conn.claims, "the failed version must not be left claimed"


def test_backup_manager_initialises_and_runs_on_such_a_backend(tmp_path):
    """End-to-end version of the reported failure: the CockroachDB-backed
    backup store initialises and a backup run completes (ok=True) instead of
    the manager being marked unavailable."""
    primary = AccountStore(f"sqlite:///{tmp_path / 'primary.db'}")
    backup_store, backup_conn = _crdb_backed_store()
    state = GatewayState()

    async def go():
        await primary.connect()
        await primary.init_schema()
        await primary.upsert_account("acct1", "ENC-A", "ENC-C", enabled=True)
        manager = BackupManager(backup_store, state)
        manager.bind_primary(primary)
        return await manager.run(triggered_by="test"), manager

    result, manager = asyncio.run(go())

    assert result["ok"] is True, result
    assert result["accounts"] == 1
    assert manager.store is backup_store
    assert state.backup_ok is True and state.last_backup_at
    assert backup_conn.claims, "the backup store's schema was initialised"
    written = "\n".join(backup_conn.statements)
    assert "INSERT INTO backup_snapshots" in written, "the snapshot claim never ran"
    assert "INSERT INTO backup_accounts" in written, "the account snapshot never ran"
    assert "advisory" not in written

