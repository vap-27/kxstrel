"""Non-sqlite backend binding contract (B5).

Every other test in the suite runs the sqlite backend, so the Postgres
placeholder rewrite and the MySQL paramstyle conversion never reached a
driver under test. A change that dropped ``*params`` from the postgres write
path therefore stayed green while breaking EVERY write on Postgres /
CockroachDB, the backup mirror included.

These tests stub the driver layer and pin one structural contract per
backend, for BOTH entry points (``_exec`` and ``_fetch_all``):

  * qmark placeholders are rewritten to a gapless ``$1..$n`` run (postgres)
    or to ``%s`` with literal ``%`` doubled (mysql);
  * the driver is handed exactly as many positional arguments as there are
    placeholders, in the same order, with the values that were passed in;
  * parameterized multi-statement SQL is refused before any driver call.

Any future change to any backend's binding has to keep these true.
"""

from __future__ import annotations

import re

import aiomysql
import pytest

from app.db import AccountStore

# One row with every column the store's readers index (`enabled`, `label`,
# `v`, `n`) so a stubbed backend can answer any fetch.
_ROW = {"id": 1, "label": "acct1", "enabled": 1, "v": "value", "n": 0}


# ── postgres stubs ───────────────────────────────────────────────────────

class _PgConn:
    def __init__(self, calls, cursor_args):
        self._calls = calls
        self._cursor_args = cursor_args

    async def execute(self, sql, *args):
        self._calls.append(("execute", sql, args))

    async def fetch(self, sql, *args):
        self._calls.append(("fetch", sql, args))
        return [dict(_ROW)]


class _Acquire:
    def __init__(self, target):
        self._target = target

    async def __aenter__(self):
        return self._target

    async def __aexit__(self, *exc):
        return False


class _PgPool:
    """Stands in for an asyncpg pool: records (method, sql, bound args)."""

    def __init__(self):
        self.calls: list[tuple[str, str, tuple]] = []
        self.cursor_args: list[tuple] = []
        self.conn = _PgConn(self.calls, self.cursor_args)

    def acquire(self):
        return _Acquire(self.conn)

    async def close(self):
        pass


# ── mysql stubs ──────────────────────────────────────────────────────────

class _MyCursor:
    def __init__(self, calls, dict_rows: bool):
        self._calls = calls
        self._rows = [dict(_ROW)] if dict_rows else [tuple(_ROW.values())]

    async def execute(self, sql, args=None):
        self._calls.append((sql, args))

    async def fetchall(self):
        return list(self._rows)

    async def fetchone(self):
        return self._rows[0] if self._rows else None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _MyConn:
    def __init__(self, calls, cursor_args):
        self._calls = calls
        self._cursor_args = cursor_args

    def cursor(self, *args):
        self._cursor_args.append(args)
        return _MyCursor(self._calls, dict_rows=bool(args))


class _MyPool:
    """Stands in for an aiomysql pool: records (sql, args) per cursor."""

    def __init__(self):
        self.calls: list[tuple[str, tuple | None]] = []
        self.cursor_args: list[tuple] = []
        self.conn = _MyConn(self.calls, self.cursor_args)

    def acquire(self):
        return _Acquire(self.conn)

    def close(self):
        pass

    async def wait_closed(self):
        pass


def _pg_store() -> tuple[AccountStore, _PgPool]:
    store = AccountStore("postgresql://user:pass@localhost:5432/db")
    pool = _PgPool()
    store._pg_pool = pool  # no connect(): the stub replaces the driver
    return store, pool


def _mysql_store() -> tuple[AccountStore, _MyPool]:
    store = AccountStore("mysql://user:pass@localhost:4000/db")
    pool = _MyPool()
    store._my_pool = pool
    return store, pool


def _assert_pg_bound(sql: str, args: tuple) -> list[int]:
    """$1..$n must be gapless and carry exactly one argument each."""
    indices = [int(m) for m in re.findall(r"\$(\d+)", sql)]
    assert indices == list(range(1, len(indices) + 1)), f"placeholder run is broken: {sql!r}"
    assert len(args) == len(indices), (
        f"{len(indices)} placeholders but {len(args)} bound arguments: {sql!r}"
    )
    return indices


# ── postgres: the write path binds ───────────────────────────────────────

async def test_postgres_exec_binds_its_parameters():
    store, pool = _pg_store()
    await store.upsert_account("acct1", "ENC-A", "ENC-C", enabled=True, meta="{}")

    assert len(pool.calls) == 1
    kind, sql, args = pool.calls[0]
    assert kind == "execute"
    assert "ON CONFLICT" in sql
    _assert_pg_bound(sql, args)
    assert args[:5] == ("acct1", "ENC-A", "ENC-C", 1, "{}")
    assert args[5] and args[6] == args[5]  # created_at / updated_at


async def test_postgres_every_write_path_binds_its_parameters():
    """The audit listed these as broken: all of them must reach the driver
    with their arguments attached."""
    store, pool = _pg_store()
    await store.upsert_account("acct1", "ENC-A", "ENC-C")
    await store.update_field("x_accounts", "acct1", "enabled", 0)
    await store.update_status("acct1", "CONNECTED", True, None)
    await store.delete_account("acct1")
    await store.set_tool_flag("search_users", False)
    await store.log_tool_usage("search_users", True, None, 7, "fp123")
    await store.log_admin_action("account.upsert", "detail", "rid")
    await store.set_meta("uptime.started_at", "2026-01-01T00:00:00+00:00")
    await store.prune_tool_usage(30)

    executes = [call for call in pool.calls if call[0] == "execute"]
    assert len(executes) >= 8, pool.calls
    for _, sql, args in executes:
        _assert_pg_bound(sql, args)

    # Spot-check order, not just arity, on two of them.
    delete = [call for call in executes if call[1].startswith("DELETE")][0]
    assert delete[2] == ("acct1",)
    meta = [call for call in executes if "INTO meta" in call[1]][0]
    assert meta[2][:2] == ("uptime.started_at", "2026-01-01T00:00:00+00:00")


async def test_postgres_fetch_all_binds_its_parameters():
    store, pool = _pg_store()
    await store.is_account_enabled("acct1")

    kind, sql, args = pool.calls[-1]
    assert kind == "fetch"
    _assert_pg_bound(sql, args)
    assert args == ("acct1",)
    assert sql.endswith("WHERE label = $1 LIMIT 1")


async def test_postgres_refuses_parameterized_multi_statement():
    store, pool = _pg_store()
    with pytest.raises(ValueError, match="single statement"):
        await store._exec("UPDATE meta SET v = ?; UPDATE meta SET v = ?", ("a", "b"))
    assert pool.calls == [], "the refusal must happen before any driver call"


# ── mysql: the converted args are bound ──────────────────────────────────

async def test_mysql_exec_binds_its_parameters():
    store, pool = _mysql_store()
    await store.log_tool_usage("search_users", True, None, 7, "fp123")

    assert len(pool.calls) == 1
    sql, args = pool.calls[0]
    assert "?" not in sql
    assert sql.count("%s") == 6
    assert args is not None and len(args) == 6
    assert args[1] == "search_users" and args[2] == 1 and args[4] == 7 and args[5] == "fp123"


async def test_mysql_escapes_percent_only_when_arguments_bind():
    store, pool = _mysql_store()
    await store._exec("UPDATE meta SET v = ? WHERE k LIKE 'pct%'", ("v",))

    sql, args = pool.calls[0]
    assert sql == "UPDATE meta SET v = %s WHERE k LIKE 'pct%%'"
    assert args == ("v",)
    # Without interpolation the statement is passed through untouched.
    assert AccountStore._mysql_prepare("SELECT '100%'", ()) == ("SELECT '100%'", None)


async def test_mysql_fetch_all_uses_a_dict_cursor_and_binds():
    store, pool = _mysql_store()
    rows = await store._fetch_all("SELECT enabled FROM x_accounts WHERE label = ?", ("acct1",))

    assert rows == [dict(_ROW)], "dict-shaped rows are what the store's readers expect"
    sql, args = pool.calls[0]
    assert sql == "SELECT enabled FROM x_accounts WHERE label = %s"
    assert args == ("acct1",)
    assert pool.cursor_args == [(aiomysql.DictCursor,)]


async def test_mysql_refuses_parameterized_multi_statement():
    store, pool = _mysql_store()
    with pytest.raises(ValueError, match="single statement"):
        await store._exec("UPDATE meta SET v = ?; UPDATE meta SET v = ?", ("a", "b"))
    assert pool.calls == []
