"""Resilient store startup: bounded retry, db creation, classification.

Feature 1 of the resilience work. Everything here is deterministic: the
driver is a stub, the backoff clock is a list the injected ``sleep`` appends
to, and jitter is a fixed value. No test opens a socket, and no test waits.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl

import pytest

from app import db as db_module
from app.db import AccountStore
from app.db_resilience import (
    DB_ERROR_KINDS,
    ERROR_HINTS,
    backoff_delay,
    classify_db_error,
    connect_and_init,
)
from app.config import Settings


# ── representative driver errors ─────────────────────────────────────────
#
# Shapes matter more than the class hierarchy: asyncpg puts the SQLSTATE on
# the exception, pymysql/aiomysql puts the server errno in args[0], and both
# are matched without importing either driver.

class _PgError(Exception):
    """asyncpg-shaped: a SQLSTATE attribute plus a message."""

    def __init__(self, sqlstate: str, message: str):
        super().__init__(message)
        self.sqlstate = sqlstate


class _MySqlError(Exception):
    """pymysql/aiomysql-shaped: args[0] is the server errno."""

    def __init__(self, errno: int, message: str):
        super().__init__(errno, message)


_DSN = "postgresql://appuser:hunter2@db.example:5432/kxstrel?sslmode=verify-full"
DSN_PASSWORD = "hunter2"


def _cases():
    return [
        # host / DNS unreachable
        pytest.param(socket.gaierror(-2, "Name or service not known"),
                     "host_unreachable", id="dns-gaierror"),
        pytest.param(ConnectionRefusedError(111, "Connection refused"),
                     "host_unreachable", id="connection-refused"),
        pytest.param(OSError(101, "Network is unreachable"),
                     "host_unreachable", id="network-unreachable"),
        pytest.param(_PgError("08006", "connection failure"),
                     "host_unreachable", id="pg-08006"),
        pytest.param(_MySqlError(2003, "Can't connect to MySQL server on 'db'"),
                     "host_unreachable", id="mysql-2003"),
        # timeout
        pytest.param(asyncio.TimeoutError(), "timeout", id="asyncio-timeout"),
        pytest.param(TimeoutError("connection timed out"),
                     "timeout", id="os-timeout"),
        pytest.param(OSError(110, "Connection timed out"), "timeout", id="errno-etimedout"),
        # authentication / permission
        pytest.param(_PgError("28P01", 'password authentication failed for user "app"'),
                     "auth_failed", id="pg-28P01"),
        pytest.param(_PgError("42501", 'permission denied for database "kxstrel"'),
                     "auth_failed", id="pg-42501-permission"),
        pytest.param(_MySqlError(1045, "Access denied for user 'app'@'1.2.3.4'"
                                      " (using password: YES)"), "auth_failed", id="mysql-1045"),
        pytest.param(Exception('role "app" does not exist'), "auth_failed", id="pg-role-missing"),
        # unknown / missing database
        pytest.param(_PgError("3D000", 'database "kxstrel" does not exist'),
                     "unknown_database", id="pg-3D000"),
        pytest.param(_MySqlError(1049, "Unknown database 'kxstrel'"),
                     "unknown_database", id="mysql-1049"),
        # TLS / certificate
        pytest.param(ssl.SSLCertVerificationError(1, "certificate verify failed"),
                     "tls_error", id="ssl-cert-verify"),
        pytest.param(_MySqlError(2026, "SSL connection error"), "tls_error", id="mysql-2026"),
        pytest.param(Exception("TLS handshake failed"), "tls_error", id="tls-handshake"),
        # too many connections
        pytest.param(_PgError("53300", "sorry, too many clients already"),
                     "too_many_connections", id="pg-53300"),
        pytest.param(_MySqlError(1040, "Too many connections"),
                     "too_many_connections", id="mysql-1040"),
        # unsupported / unknown DSN
        pytest.param(ValueError("DATABASE_URL must use mysql://, mariadb://, "
                                "postgresql://, postgres://, or sqlite://"),
                     "unsupported_dsn", id="bad-scheme"),
        pytest.param(ValueError("sqlite:///:memory: is not supported because this "
                                "store uses short-lived connections; use sqlite:///path.db"),
                     "unsupported_dsn", id="memory-sqlite"),
        # missing driver
        pytest.param(RuntimeError("DATABASE_URL is postgres but asyncpg is not installed"),
                     "driver_missing", id="asyncpg-missing"),
        pytest.param(ModuleNotFoundError("No module named 'aiomysql'"),
                     "driver_missing", id="aiomysql-missing"),
        # anything else keeps its own explicit bucket
        pytest.param(Exception("something odd happened"), "unknown", id="uncategorised"),
    ]


@pytest.mark.parametrize("exc,expected", _cases())
def test_classification_maps_driver_errors_to_a_stable_kind(exc, expected):
    kind, hint = classify_db_error(exc)
    assert kind == expected
    assert kind in DB_ERROR_KINDS, "the kind must come from the closed set"
    assert hint and hint == ERROR_HINTS[kind]


@pytest.mark.parametrize("exc,expected", _cases())
def test_hint_is_actionable_and_never_carries_the_dsn_or_a_password(exc, expected):
    kind, hint = classify_db_error(exc)
    # Nothing that identifies the target or its credentials: the DSN, its
    # host, its user, its password. (Scheme names alone are fine: the
    # unsupported-DSN hint lists what IS supported.)
    for secret in (DSN_PASSWORD, "appuser", "db.example", "sslmode=", _DSN):
        assert secret not in hint, f"{secret!r} leaked into the hint for {kind}"
    # Every hint names something concrete to do/check.
    assert any(word in hint for word in ("check", "install", "create", "close", "read"))


def test_plain_exception_with_a_password_in_its_message_is_still_safe():
    """The hint is static; the sanitized message is what carries driver text."""
    exc = _MySqlError(1045, "Access denied for user 'app'@'db' (using password: YES) "
                            f"password={DSN_PASSWORD} dsn={_DSN}")
    kind, hint = classify_db_error(exc)
    assert kind == "auth_failed"
    assert DSN_PASSWORD not in hint and "postgresql://" not in hint


def test_mysql_errno_only_wins_when_the_message_does_not_contradict_it():
    """A coded error is classified by its code, not by loose text."""
    kind, _ = classify_db_error(_MySqlError(1049, "Unknown database 'x'"))
    assert kind == "unknown_database"
    kind, _ = classify_db_error(_MySqlError(1040, "Too many connections"))
    assert kind == "too_many_connections"


# ── backoff ──────────────────────────────────────────────────────────────

def test_backoff_is_exponential_capped_and_jittered():
    def one():
        return 1.0  # fixed jitter makes the maths exact

    assert [backoff_delay(n, 1.0, 15.0, one) for n in range(1, 6)] == [1.0, 2.0, 4.0, 8.0, 15.0]
    assert backoff_delay(9, 1.0, 15.0, one) == 15.0, "the cap must hold for every attempt"
    # Jitter is bounded by the delay itself, so the cap is never exceeded.
    assert backoff_delay(9, 1.0, 15.0, lambda: 1.0) <= 15.0
    assert backoff_delay(1, 1.0, 15.0, lambda: 0.0) == 0.0
    # Zero base or zero cap disables waiting entirely (a deliberate setting).
    assert backoff_delay(5, 0.0, 15.0, one) == 0.0
    assert backoff_delay(5, 1.0, 0.0, one) == 0.0


# ── retry loop ───────────────────────────────────────────────────────────

class _StubStore:
    """A store whose driver is a scripted list of failures. No I/O at all."""

    def __init__(self, failures: int = 0, error: BaseException | None = None,
                 label: str = "primary", backend: str = "sqlite",
                 database_name: str = "kxstrel", creation=(False, None)):
        self.label = label
        self.backend = backend
        self.database_name = database_name
        self.failures = failures
        self.error = error or ConnectionRefusedError(111, "Connection refused")
        self.creation = creation
        self.connect_calls = 0
        self.init_calls = 0
        self.close_calls = 0
        self.creation_calls = 0

    async def connect(self) -> None:
        self.connect_calls += 1
        if self.connect_calls <= self.failures:
            raise self.error

    async def init_schema(self) -> None:
        self.init_calls += 1

    async def close(self) -> None:
        self.close_calls += 1

    async def create_database_if_missing(self, *, connect=None):
        self.creation_calls += 1
        return self.creation


class _Sleeps:
    """The injected sleep: records the delay instead of waiting on it."""

    def __init__(self):
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


def _settings(**overrides) -> Settings:
    base = dict(DB_CONNECT_MAX_ATTEMPTS=4, DB_CONNECT_BASE_DELAY_SECONDS=1.0,
                DB_CONNECT_MAX_DELAY_SECONDS=15.0)
    base.update(overrides)
    return Settings(**base)


@pytest.mark.parametrize("failures", [1, 2, 3])
async def test_retry_succeeds_after_n_transient_failures(failures):
    store, sleeps = _StubStore(failures=failures), _Sleeps()
    outcome = await connect_and_init(store, _settings(), sleep=sleeps, rand=lambda: 1.0)

    assert outcome.ok is True
    assert outcome.attempts == failures + 1, "each attempt must be one connect()"
    assert store.connect_calls == failures + 1
    assert store.init_calls == 1, "schema init runs once, on the successful attempt"
    # Delays are the capped exponential run for the attempts that failed.
    assert sleeps.delays == [min(1.0 * 2 ** (n - 1), 15.0) for n in range(1, failures + 1)]
    assert store.close_calls == failures, "a half-open pool must not survive an attempt"


async def test_first_attempt_is_immediate():
    """No sleep at all before the first connect, and none when it works."""
    store, sleeps = _StubStore(), _Sleeps()
    outcome = await connect_and_init(store, _settings(), sleep=sleeps, rand=lambda: 1.0)

    assert outcome.ok is True and outcome.attempts == 1
    assert sleeps.delays == [], "the first attempt must never wait"


async def test_gives_up_after_the_configured_max_and_reports_the_kind():
    store, sleeps = _StubStore(failures=99), _Sleeps()
    outcome = await connect_and_init(store, _settings(DB_CONNECT_MAX_ATTEMPTS=3),
                                    sleep=sleeps, rand=lambda: 1.0)

    assert outcome.ok is False
    assert outcome.attempts == 3, "exactly the configured number of attempts"
    assert store.connect_calls == 3, "and no more connects than attempts"
    assert sleeps.delays == [1.0, 2.0], "one sleep between attempts, none after the last"
    assert outcome.error_kind == "host_unreachable"
    assert outcome.hint in ERROR_HINTS.values()
    assert outcome.message and "ConnectionRefusedError" in outcome.message


async def test_total_wait_is_bounded_by_the_policy():
    """Bounded in total: attempts x capped delay, never an open-ended loop."""
    store, sleeps = _StubStore(failures=99), _Sleeps()
    await connect_and_init(store, _settings(DB_CONNECT_MAX_ATTEMPTS=5,
                                            DB_CONNECT_BASE_DELAY_SECONDS=2.0,
                                            DB_CONNECT_MAX_DELAY_SECONDS=5.0),
                           sleep=sleeps, rand=lambda: 1.0)
    assert sleeps.delays == [2.0, 4.0, 5.0, 5.0]
    assert sum(sleeps.delays) == 16.0
    assert len(sleeps.delays) == 4, "5 attempts means 4 waits"


@pytest.mark.parametrize("configured,expected_attempts", [(0, 1), (-3, 1), (3, 3), (10_000, 10)])
async def test_attempt_policy_is_clamped(configured, expected_attempts):
    """A nonsensical .env cannot make the retry unbounded (or empty)."""
    store, sleeps = _StubStore(failures=99_999), _Sleeps()
    outcome = await connect_and_init(store, _settings(DB_CONNECT_MAX_ATTEMPTS=configured),
                                    sleep=sleeps, rand=lambda: 1.0)
    assert outcome.attempts == expected_attempts
    assert store.connect_calls == expected_attempts


async def test_unsupported_dsn_is_not_retried():
    """A configuration error cannot be fixed by waiting."""
    store = _StubStore(failures=99,
                       error=ValueError("DATABASE_URL must use mysql://, mariadb://, "
                                        "postgresql://, postgres://, or sqlite://"))
    sleeps = _Sleeps()
    outcome = await connect_and_init(store, _settings(), sleep=sleeps, rand=lambda: 1.0)

    assert outcome.ok is False
    assert outcome.error_kind == "unsupported_dsn"
    assert store.connect_calls == 1 and sleeps.delays == []


async def test_failure_never_raises_and_never_leaks_the_dsn(caplog):
    """The caller always reaches its degraded-mode path, and the log line is
    sanitized: no password, no full DSN, and truncated."""
    caplog.set_level(logging.INFO, logger="kxstrel-x-mcp.db")
    store = _StubStore(failures=99, error=ConnectionRefusedError(
        111, f"could not connect to {_DSN}"))
    outcome = await connect_and_init(store, _settings(DB_CONNECT_MAX_ATTEMPTS=2),
                                    sleep=_Sleeps(), rand=lambda: 1.0)

    assert outcome.ok is False
    assert outcome.message and DSN_PASSWORD not in outcome.message
    assert _DSN not in outcome.message, "the DSN must be redacted, not echoed"
    assert len(outcome.message) <= 300, "messages are truncated, never a raw dump"
    everything = "\n".join(caplog.messages)
    assert DSN_PASSWORD not in everything
    assert _DSN not in everything
    assert any("unavailable after 2 attempt(s)" in m for m in caplog.messages), caplog.messages


async def test_default_policy_is_used_when_settings_say_nothing():
    """A caller passing a bare object still gets the documented defaults."""
    class Bare:
        pass

    store, sleeps = _StubStore(failures=99), _Sleeps()
    outcome = await connect_and_init(store, Bare(), sleep=sleeps, rand=lambda: 1.0)
    assert store.connect_calls == 5, "DB_CONNECT_MAX_ATTEMPTS default is 5"
    assert sleeps.delays == [1.0, 2.0, 4.0, 8.0], "base 1.0, capped at 15.0"


async def test_every_attempt_is_logged_with_its_kind(caplog):
    """One line per attempt, plus a final summary — the operator can see the
    whole story without turning on DEBUG."""
    caplog.set_level(logging.INFO, logger="kxstrel-x-mcp.db")
    store = _StubStore(failures=99)
    outcome = await connect_and_init(store, _settings(DB_CONNECT_MAX_ATTEMPTS=4),
                                    sleep=_Sleeps(), rand=lambda: 1.0)

    attempts = [m for m in caplog.messages if "connect attempt" in m]
    assert [m.split("attempt ")[1].split("/")[0] for m in attempts] == ["1", "2", "3", "4"]
    assert all("kind=host_unreachable" in m for m in attempts)
    assert any("retrying in" in m for m in caplog.messages)
    summary = [m for m in caplog.messages if "unavailable after 4 attempt(s)" in m]
    assert summary and outcome.hint in summary[0], "the summary must carry the hint"


async def test_success_is_logged_with_the_attempt_count(caplog):
    caplog.set_level(logging.INFO, logger="kxstrel-x-mcp.db")
    store = _StubStore(failures=2)
    await connect_and_init(store, _settings(DB_CONNECT_MAX_ATTEMPTS=3),
                           sleep=_Sleeps(), rand=lambda: 1.0)
    assert any("ready after 3 attempt(s)" in m for m in caplog.messages), caplog.messages


# ── best-effort CREATE DATABASE ──────────────────────────────────────────


def test_identifier_validation_refuses_anything_but_a_plain_name():
    assert db_module.is_plain_identifier("kxstrel")
    assert db_module.is_plain_identifier("x_mcp_2")
    assert db_module.is_plain_identifier("_" + "a" * 62)          # 63 chars is the limit
    for bad in ("", "x;DROP TABLE t", "x`y", 'x"y', "x y", "x.y", "2kxstrel",
                "x\n", "kxstrel--", "a" * 64, "%s", "kxstrel\x00"):
        assert not db_module.is_plain_identifier(bad), bad


def test_create_statement_is_dialect_correct():
    assert db_module.create_database_statement("mysql", "kxstrel") == \
        "CREATE DATABASE IF NOT EXISTS `kxstrel`"
    # Postgres has no CREATE DATABASE IF NOT EXISTS — emitting one would be a
    # syntax error, so the plain form is used and "already exists" is treated
    # as success by the caller.
    assert db_module.create_database_statement("postgres", "kxstrel") == \
        'CREATE DATABASE "kxstrel"'


def test_database_name_comes_from_the_same_parser_as_the_backend():
    assert AccountStore("mysql://u:p@h:4000/kxstrel").database_name == "kxstrel"
    assert AccountStore("mysql://u:p@h:4000/custom_db").database_name == "custom_db"
    # Placeholder/system databases automatically normalize to kxstrel
    assert AccountStore("mysql://u:p@h:4000/sys").database_name == "kxstrel"
    assert AccountStore("mysql://u:p@h:4000/test").database_name == "kxstrel"
    assert AccountStore("mysql://u:p@h:4000").database_name == "kxstrel"
    assert AccountStore("mysql://u:p@h:4000/").database_name == "kxstrel"
    assert AccountStore("postgresql://u:p@h:5432/kxstrel").database_name == "kxstrel"
    assert AccountStore("postgresql://u:p@h:5432/").database_name == "kxstrel"
    assert AccountStore("sqlite:///./data/x.db").database_name == ""


class _FakeCursor:
    def __init__(self, conn):
        self._conn = conn

    async def execute(self, sql, args=None):
        self._conn.statements.append(sql)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeMySqlConn:
    def __init__(self):
        self.statements: list[str] = []
        self.closed = False

    def cursor(self, *args):
        return _FakeCursor(self)

    def close(self):
        self.closed = True


class _FakePgConn:
    def __init__(self):
        self.statements: list[str] = []
        self.closed = False

    async def execute(self, sql, *args):
        self.statements.append(sql)

    async def close(self):
        self.closed = True


async def test_mysql_creation_targets_the_maintenance_connection():
    store = AccountStore("mysql://u:p@h:4000/kxstrel")
    conn = _FakeMySqlConn()
    seen = []

    async def connect(s, maintenance_db):
        seen.append(maintenance_db)
        return conn

    created, error = await store.create_database_if_missing(connect=connect)

    assert (created, error) == (True, None)
    assert seen == [""], "MySQL has no default maintenance database (db=None)"
    assert conn.statements == ["CREATE DATABASE IF NOT EXISTS `kxstrel`"]
    assert conn.closed, "the throwaway connection must not leak"


async def test_postgres_creation_targets_the_maintenance_database():
    store = AccountStore("postgresql://u:p@h:5432/kxstrel")
    conn = _FakePgConn()
    seen = []

    async def connect(s, maintenance_db):
        seen.append(maintenance_db)
        return conn

    created, error = await store.create_database_if_missing(connect=connect)

    assert (created, error) == (True, None)
    assert seen == ["postgres"]
    assert conn.statements == ['CREATE DATABASE "kxstrel"']
    assert conn.closed


async def test_creation_refuses_a_non_identifier_without_touching_the_server():
    """No quoting tricks: the DDL is never built from an unvalidated name."""
    store = AccountStore("postgresql://u:p@h:5432/kxstrel%22%3BDROP")
    opened = []

    async def connect(s, maintenance_db):  # pragma: no cover - must not run
        opened.append(maintenance_db)
        return _FakePgConn()

    created, error = await store.create_database_if_missing(connect=connect)

    assert created is False
    assert isinstance(error, ValueError)
    assert "not a plain identifier" in str(error)
    assert opened == [], "no connection may be opened for a refused name"


async def test_creation_is_never_attempted_for_sqlite(tmp_path):
    """A sqlite "database" is a file connect() creates; there is nothing to
    CREATE DATABASE, and the driver must never be asked to."""
    store = AccountStore(f"sqlite:///{tmp_path / 'x.db'}")
    opened = []

    async def connect(s, maintenance_db):  # pragma: no cover - must not run
        opened.append(maintenance_db)
        return _FakePgConn()

    assert store.backend == "sqlite"
    assert await store.create_database_if_missing(connect=connect) == (False, None)
    assert opened == []

    # ...and through the retry loop a missing sqlite file never triggers it.
    stub = _StubStore(failures=99, error=FileNotFoundError(2, "No such file"))
    await connect_and_init(stub, _settings(DB_CONNECT_MAX_ATTEMPTS=2),
                           sleep=_Sleeps(), rand=lambda: 1.0)
    assert stub.creation_calls == 0


async def test_server_denial_is_reported_not_raised():
    """CockroachDB Serverless / read-only TiDB users deny CREATE DATABASE."""
    store = AccountStore("postgresql://u:p@h:26257/kxstrel")
    exc = _PgError("42501", "user u does not have CREATE privilege on database kxstrel")

    async def connect(s, maintenance_db):
        raise exc

    created, error = await store.create_database_if_missing(connect=connect)
    assert created is False and error is exc


async def test_postgres_already_exists_counts_as_created():
    """42P04 means the database is there, which is all the caller wanted."""
    store = AccountStore("postgresql://u:p@h:5432/kxstrel")
    exc = _PgError("42P04", 'database "kxstrel" already exists')

    async def connect(s, maintenance_db):
        raise exc

    assert await store.create_database_if_missing(connect=connect) == (True, None)


async def test_missing_database_triggers_creation_then_reinit(caplog):
    """End to end through the retry loop: unknown database -> create ->
    connect succeeds, without a single backoff wait."""
    caplog.set_level(logging.INFO, logger="kxstrel-x-mcp.db")
    exc = _PgError("3D000", 'database "kxstrel" does not exist')
    store = _StubStore(failures=1, error=exc, backend="postgres",
                       database_name="kxstrel", creation=(True, None))
    sleeps = _Sleeps()

    outcome = await connect_and_init(store, _settings(), sleep=sleeps, rand=lambda: 1.0)

    assert outcome.ok is True
    assert outcome.database_created is True
    assert outcome.attempts == 2 and store.creation_calls == 1
    assert sleeps.delays == [], "creation is followed by an immediate retry"
    assert any("created the missing database" in m for m in caplog.messages)


async def test_creation_denial_is_logged_with_a_fix_and_is_non_fatal(caplog):
    caplog.set_level(logging.WARNING, logger="kxstrel-x-mcp.db")
    exc = _PgError("3D000", 'database "kxstrel" does not exist')
    denied = _PgError("42501", "does not have CREATE privilege")
    store = _StubStore(failures=99, error=exc, backend="postgres",
                       database_name="kxstrel", creation=(False, denied))
    sleeps = _Sleeps()

    outcome = await connect_and_init(store, _settings(DB_CONNECT_MAX_ATTEMPTS=3),
                                    sleep=sleeps, rand=lambda: 1.0)

    assert outcome.ok is False, "a store that still cannot connect is a degraded start"
    assert outcome.error_kind == "unknown_database"
    assert store.creation_calls == 1, "creation is attempted once, not per retry"
    denied_lines = [m for m in caplog.messages if "could not create the missing database" in m]
    assert denied_lines, caplog.messages
    assert "Create it once in the provider console" in denied_lines[0]
    assert "auth_failed" in denied_lines[0] or "unknown" in denied_lines[0]


async def test_creation_is_not_attempted_for_a_non_missing_database_error():
    store = _StubStore(failures=99, error=ConnectionRefusedError(111, "Connection refused"))
    await connect_and_init(store, _settings(), sleep=_Sleeps(), rand=lambda: 1.0)
    assert store.creation_calls == 0


async def test_creation_that_does_not_apply_is_logged_once(caplog):
    """sqlite / a DSN naming no database: say so instead of looping silently."""
    caplog.set_level(logging.WARNING, logger="kxstrel-x-mcp.db")
    exc = _PgError("3D000", 'database "kxstrel" does not exist')
    store = _StubStore(failures=99, error=exc, backend="postgres",
                       database_name="", creation=(False, None))
    outcome = await connect_and_init(store, _settings(DB_CONNECT_MAX_ATTEMPTS=2),
                                    sleep=_Sleeps(), rand=lambda: 1.0)
    assert outcome.ok is False
    assert any("cannot be auto-created" in m for m in caplog.messages)
