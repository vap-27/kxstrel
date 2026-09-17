"""Persistent storage: TiDB (MySQL), Postgres, or sqlite — one interface.

Primary store (DATABASE_URL) holds accounts (encrypted credentials), tool
flags, usage logs, and the admin audit trail. Versioned migrations run on
startup. An optional backup store (BACKUP_DATABASE_URL, Postgres-compatible
e.g. CockroachDB) keeps append-only snapshots of the critical tables on a
schedule (see backup.py).

Only ciphertext is stored. Plaintext credentials exist in memory only and
are never logged, never returned by list APIs.

SQL handling rules:
- placeholders are the qmark style (`?`) in every dialect; the Postgres
  adapter rewrites them quote-aware, SQLite/MySQL consume them natively;
- statement splitting is quote-aware and refuses parameterized
  multi-statement input rather than executing the same params everywhere.
"""

from __future__ import annotations

import asyncio
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Iterator
from urllib.parse import unquote, urlparse, urlunparse

from .logging_setup import get_logger, sanitize_error
from .models import AccountRecord

log = get_logger("kxstrel-x-mcp.db")

# ─────────────────────────────────────────────────────────────────────────
# Migration runner: one portable atomic claim, no vendor lock.
#
# Two instances booting at once must not both decide a version is unapplied
# and both run its DDL. The arbiter is the PRIMARY KEY on
# schema_migrations.version, which Postgres, CockroachDB, MySQL and SQLite
# all enforce atomically on INSERT (ON CONFLICT DO NOTHING / ON DUPLICATE
# KEY). Per version the runner:
#
#   claim  INSERT (version, <unique claim token>, applied_at = NULL). Exactly
#          one instance is let through; a loser sees the winner's token.
#   read   SELECT the row back and decide from it: our token means the claim
#          is ours, any other token means someone else owns it, a non-NULL
#          applied_at means the version is already applied.
#   ddl    only the owner runs the statements.
#   settle UPDATE applied_at (applied) or DELETE the claim row (failed, so
#          the version is NOT marked applied and the next boot retries it).
#
# A row counts as applied only once applied_at is set, so a crash or a
# failing statement can never leave a half-applied version behind. Ownership
# is decided by reading the row rather than by a RETURNING row count, which
# keeps every statement here to plain INSERT/SELECT/UPDATE/DELETE — nothing
# CockroachDB, MySQL or SQLite lacks.
#
# This replaced pg_advisory_lock / GET_LOCK, which CockroachDB does not
# implement ("unknown function: pg_advisory_lock()"): the backup store — a
# CockroachDB database — failed to initialise, so scheduled backups never ran.
# The claim above is what actually prevents two instances applying the same
# migration, so no vendor-specific lock is used or needed any more.
# ─────────────────────────────────────────────────────────────────────────

_SCHEMA_MIGRATIONS_DDL = (
    "CREATE TABLE IF NOT EXISTS schema_migrations "
    "(version INTEGER PRIMARY KEY, name TEXT, applied_at TEXT)"
)

# How long to wait for another instance's in-flight claim before assuming its
# owner died and re-running the DDL (every migration is IF NOT EXISTS).
_MIGRATION_CLAIM_WAIT_SECONDS = 60.0
_MIGRATION_CLAIM_POLL_SECONDS = 0.25

# busy timeout so a second process waits for a writer instead of failing.
_SQLITE_BUSY_TIMEOUT_SECONDS = 30


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scan_sql(sql: str, *, backslash_escapes: bool = False) -> Iterator[tuple[str, bool]]:
    """Yield ``(text, is_code)`` pieces of a SQL string.

    ``is_code`` is False inside string literals, quoted identifiers and
    comments, so callers can ignore characters there. Raises ValueError for
    input that cannot be scanned safely (unterminated literal/comment):
    guessing in that case would corrupt data or splice statements.

    ``backslash_escapes`` selects the literal dialect and MUST match the
    backend the SQL is going to: MySQL treats ``\\`` inside quote delimiters
    as an escape (``'C:\\'`` is an unterminated literal there), while
    standard SQL — Postgres, SQLite — does not, so the same text is a valid
    literal ending in a backslash. Scanning a standard-SQL literal with MySQL
    rules would reject valid SQL; the reverse would mis-split statements.
    """
    i, n = 0, len(sql)
    quote: str | None = None
    while i < n:
        ch = sql[i]
        if quote is not None:
            if backslash_escapes and ch == "\\" and quote in ("'", '"') and i + 1 < n:
                yield sql[i:i + 2], False  # backslash escape (MySQL strings only)
                i += 2
                continue
            if ch == quote:
                if i + 1 < n and sql[i + 1] == quote:
                    yield sql[i:i + 2], False  # doubled-quote escape
                    i += 2
                    continue
                quote = None
            yield ch, False
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            yield ch, False
            i += 1
            continue
        if ch == "-" and sql.startswith("--", i):
            end = sql.find("\n", i)
            end = n if end < 0 else end
            yield sql[i:end], False
            i = end
            continue
        if ch == "/" and sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            if end < 0:
                raise ValueError("unterminated block comment in SQL")
            yield sql[i:end + 2], False
            i = end + 2
            continue
        yield ch, True
        i += 1
    if quote is not None:
        raise ValueError("unterminated string literal in SQL")


# ─────────────────────────────────────────────────────────────────────────
# Dialect SQL. All statements are idempotent (IF NOT EXISTS) so the
# migration runner is safe on fresh and pre-existing deployments alike.
# ─────────────────────────────────────────────────────────────────────────

def _accounts_sql(backend: str) -> str:
    if backend == "mysql":
        return """
        CREATE TABLE IF NOT EXISTS x_accounts (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            label VARCHAR(64) UNIQUE NOT NULL,
            enc_auth_token TEXT NOT NULL,
            enc_ct0 TEXT NOT NULL,
            enabled INT NOT NULL DEFAULT 1,
            status VARCHAR(32) NOT NULL DEFAULT 'NOT_CONFIGURED',
            last_checked_at TEXT,
            last_check_ok INT,
            last_error TEXT,
            meta TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    serial = "SERIAL PRIMARY KEY" if backend == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT"
    return f"""
    CREATE TABLE IF NOT EXISTS x_accounts (
        id {serial},
        label TEXT UNIQUE NOT NULL,
        enc_auth_token TEXT NOT NULL,
        enc_ct0 TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'NOT_CONFIGURED',
        last_checked_at TEXT,
        last_check_ok INTEGER,
        last_error TEXT,
        meta TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """


def _tool_flags_sql(backend: str) -> str:
    name = "VARCHAR(128)" if backend == "mysql" else "TEXT"
    return f"""
    CREATE TABLE IF NOT EXISTS tool_flags (
        tool_name {name} PRIMARY KEY,
        enabled INTEGER NOT NULL DEFAULT 1,
        updated_at TEXT NOT NULL
    )
    """


def _tool_usage_sql(backend: str) -> str:
    if backend == "mysql":
        return """
        CREATE TABLE IF NOT EXISTS tool_usage (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            ts VARCHAR(64) NOT NULL,
            tool_name VARCHAR(128) NOT NULL,
            ok INT NOT NULL,
            error TEXT,
            duration_ms INT,
            caller_fp VARCHAR(32),
            INDEX idx_tool_usage_ts (ts),
            INDEX idx_tool_usage_tool (tool_name)
        )
        """
    serial = "SERIAL PRIMARY KEY" if backend == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT"
    idx = ("CREATE INDEX IF NOT EXISTS idx_tool_usage_ts ON tool_usage (ts);\n"
           "CREATE INDEX IF NOT EXISTS idx_tool_usage_tool ON tool_usage (tool_name);"
           if backend != "mysql" else "")
    return f"""
    CREATE TABLE IF NOT EXISTS tool_usage (
        id {serial},
        ts TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        ok INTEGER NOT NULL,
        error TEXT,
        duration_ms INTEGER,
        caller_fp TEXT
    );
    {idx}
    """


def _admin_audit_sql(backend: str) -> str:
    if backend == "mysql":
        return """
        CREATE TABLE IF NOT EXISTS admin_audit (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            ts TEXT NOT NULL,
            action VARCHAR(64) NOT NULL,
            detail TEXT,
            request_id VARCHAR(32)
        )
        """
    serial = "SERIAL PRIMARY KEY" if backend == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT"
    return f"""
    CREATE TABLE IF NOT EXISTS admin_audit (
        id {serial},
        ts TEXT NOT NULL,
        action TEXT NOT NULL,
        detail TEXT,
        request_id TEXT
    )
    """


def _meta_sql(backend: str) -> str:
    key = "VARCHAR(64)" if backend == "mysql" else "TEXT"
    return f"""
    CREATE TABLE IF NOT EXISTS meta (
        k {key} PRIMARY KEY,
        v TEXT,
        updated_at TEXT NOT NULL
    )
    """


def _claim_marker(name: str, token: str) -> str:
    """``name`` column value identifying this instance's claim on a version."""
    return f"{name}#claim-{token}"


def _backup_snapshot_sql(backend: str) -> list[str]:
    """Append-only snapshot tables in the BACKUP store (migration 7).

    Every backup run writes a new partition keyed by ``snapshot_at`` (UTC
    ISO-8601 with microseconds) instead of overwriting the previous run, so
    a bad state on the primary can never destroy the last good copy. The
    index row in ``backup_snapshots`` is the run's authoritative claim: it
    is written first, and only a run that also finished its rows is kept.

    These tables are only meaningful on the backup store, but they are
    created by every store's migration runner because the secondary store is
    an ordinary AccountStore and runs ``init_schema()`` itself.
    """
    key64 = "VARCHAR(64)" if backend == "mysql" else "TEXT"
    key128 = "VARCHAR(128)" if backend == "mysql" else "TEXT"
    short = "VARCHAR(32)" if backend == "mysql" else "TEXT"
    if backend == "mysql":
        # MySQL cannot index a TEXT column without a prefix length, so the
        # audit index lives inline on a VARCHAR instead.
        audit = f"""
        CREATE TABLE IF NOT EXISTS backup_admin_audit (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            snapshot_at {key64} NOT NULL,
            ts TEXT,
            action {key64},
            detail TEXT,
            request_id {short},
            INDEX idx_backup_admin_audit_snapshot (snapshot_at)
        )
        """
        extra: list[str] = []
    else:
        serial = "SERIAL PRIMARY KEY" if backend == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT"
        audit = f"""
        CREATE TABLE IF NOT EXISTS backup_admin_audit (
            id {serial},
            snapshot_at {key64} NOT NULL,
            ts TEXT,
            action TEXT,
            detail TEXT,
            request_id TEXT
        )
        """
        extra = ["CREATE INDEX IF NOT EXISTS idx_backup_admin_audit_snapshot"
                 " ON backup_admin_audit (snapshot_at)"]
    return [
        f"""
        CREATE TABLE IF NOT EXISTS backup_snapshots (
            snapshot_at {key64} PRIMARY KEY,
            created_at TEXT NOT NULL,
            triggered_by {key64},
            account_rows INTEGER NOT NULL DEFAULT 0,
            migration_rows INTEGER NOT NULL DEFAULT 0,
            tool_flag_rows INTEGER NOT NULL DEFAULT 0,
            audit_rows INTEGER NOT NULL DEFAULT 0
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS backup_accounts (
            snapshot_at {key64} NOT NULL,
            label {key64} NOT NULL,
            enc_auth_token TEXT NOT NULL,
            enc_ct0 TEXT NOT NULL,
            enabled INTEGER NOT NULL,
            status {short},
            last_checked_at TEXT,
            last_check_ok INTEGER,
            last_error TEXT,
            meta TEXT,
            created_at TEXT,
            updated_at TEXT,
            PRIMARY KEY (snapshot_at, label)
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS backup_schema_migrations (
            snapshot_at {key64} NOT NULL,
            version INTEGER NOT NULL,
            name TEXT,
            applied_at TEXT,
            PRIMARY KEY (snapshot_at, version)
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS backup_tool_flags (
            snapshot_at {key64} NOT NULL,
            tool_name {key128} NOT NULL,
            enabled INTEGER NOT NULL,
            updated_at TEXT,
            PRIMARY KEY (snapshot_at, tool_name)
        )
        """,
        audit,
        *extra,
    ]


# NOTE: migrations 1-4 also ran against the backup store, which is how the
# legacy mirror tables (x_accounts, tool_flags, admin_audit there) came to
# exist. The mirror design overwrote the previous run, so those tables are
# now leftovers; the snapshot tables above replaced them. They are
# deliberately NOT dropped (destructive, and a store may still hold the last
# mirrored copy of an account).
def _migrations_for(backend: str) -> list[tuple[int, str, list[str]]]:
    return [
        (1, "x_accounts", [_accounts_sql(backend)]),
        (2, "tool_flags", [_tool_flags_sql(backend)]),
        (3, "tool_usage", [_tool_usage_sql(backend)]),
        (4, "admin_audit", [_admin_audit_sql(backend)]),
        (5, "schema_migrations", [_SCHEMA_MIGRATIONS_DDL]),
        (6, "meta", [_meta_sql(backend)]),
        (7, "backup_snapshots", _backup_snapshot_sql(backend)),
    ]


def _row_to_record(row) -> AccountRecord:
    get = (lambda k: row[k]) if not isinstance(row, dict) else (lambda k: row[k])
    return AccountRecord(
        id=get("id"),
        label=get("label"),
        enc_auth_token=get("enc_auth_token"),
        enc_ct0=get("enc_ct0"),
        enabled=bool(get("enabled")),
        status=get("status"),
        last_checked_at=get("last_checked_at"),
        last_check_ok=None if get("last_check_ok") is None else bool(get("last_check_ok")),
        last_error=get("last_error"),
        meta=get("meta") or "{}",
        created_at=get("created_at"),
        updated_at=get("updated_at"),
    )


def _ssl_context():
    """TLS context from the certifi bundle (bundled with httpx). TiDB Cloud
    and CockroachDB Cloud both use publicly-trusted CAs."""
    import ssl

    ctx = ssl.create_default_context()
    try:
        import certifi

        ctx.load_verify_locations(certifi.where())
    except Exception:  # pragma: no cover - system store fallback
        pass
    return ctx


# ─────────────────────────────────────────────────────────────────────────
# Best-effort CREATE DATABASE for a DSN whose database does not exist yet.
#
# On TiDB Cloud / Render / CockroachDB the database usually has to exist
# before the gateway can use it, and "Unknown database 'x'" at startup is
# the operator's first encounter with that. When — and only when — the
# connection failed because the database itself is missing, the store tries
# to create it by connecting to the server's maintenance database.
#
# Hard rules:
# - sqlite is NEVER included: its file is created by connect() itself, and a
#   "missing database" can only mean a wrong path, never a thing to create;
# - the name comes from the operator's DSN, but it is still validated as a
#   plain identifier before it is interpolated into DDL (no injection, no
#   quoting tricks): letters/digits/underscore, max 63 chars, no leading
#   digit;
# - best effort: a server that denies it (typical on CockroachDB Serverless)
#   or does not implement it logs and continues to the normal failure path.
#   This function never raises.
# ─────────────────────────────────────────────────────────────────────────

_PLAIN_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")
# 63 is Postgres' identifier limit; MySQL's is 64. The stricter one applies.
_MAX_IDENTIFIER_LENGTH = 63

# The database a CREATE DATABASE statement is issued from. MySQL has no
# default maintenance database (connect without `db`); Postgres' conventional
# one is `postgres`, which every managed Postgres/CockroachDB exposes.
_MAINTENANCE_DATABASE = {"mysql": "", "postgres": "postgres"}

_MAINTENANCE_CONNECT_TIMEOUT_SECONDS = 10.0


def is_plain_identifier(name: str) -> bool:
    """True when ``name`` is safe to interpolate as a quoted identifier.

    Deliberately strict: this value is pasted into DDL, so anything with a
    quote, a space, a dot, a backtick, a NUL or a ``;`` is refused rather
    than escaped — the gateway only ever needs ordinary database names.
    """
    return (
        bool(name)
        and len(name) <= _MAX_IDENTIFIER_LENGTH
        and bool(_PLAIN_IDENTIFIER_RE.match(name))
    )


def create_database_statement(backend: str, name: str) -> str:
    """The dialect's CREATE DATABASE statement for a validated identifier.

    MySQL (TiDB) supports ``IF NOT EXISTS`` natively, so it is used there.
    Postgres has no ``IF NOT EXISTS`` for CREATE DATABASE — the statement
    would be a syntax error — so the plain form is emitted and an "already
    exists" answer from the server is treated as success by the caller.
    CockroachDB accepts the plain form too.
    """
    if backend == "mysql":
        return f"CREATE DATABASE IF NOT EXISTS `{name}`"
    return f'CREATE DATABASE "{name}"'


def _pg_dsn_and_tls(database_url: str) -> tuple[str, dict]:
    """``(asyncpg DSN, extra connect kwargs)`` for a postgres-family URL.

    TLS by default for remote hosts: asyncpg connects cleartext when the DSN
    carries no sslmode, which is never what we want for managed databases.
    sslmode is stripped and an explicit certifi-verified context is passed
    instead (covers verify-full CRDB DSNs too).
    """
    dsn = database_url.replace("postgres://", "postgresql://", 1)
    kwargs: dict = {}
    host = urlparse(dsn).hostname or ""
    if "sslmode=" in dsn or host not in ("localhost", "127.0.0.1", "::1"):
        kwargs["ssl"] = _ssl_context()
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

        parts = urlsplit(dsn)
        q = [(k, v) for k, v in parse_qsl(parts.query) if k != "sslmode"]
        dsn = urlunsplit(parts._replace(query=urlencode(q)))
    return dsn, kwargs


def _pg_maintenance_dsn(database_url: str, maintenance_db: str) -> tuple[str, dict]:
    """The same connection target, but pointed at the maintenance database."""
    from urllib.parse import urlsplit, urlunsplit

    dsn, kwargs = _pg_dsn_and_tls(database_url)
    return urlunsplit(urlsplit(dsn)._replace(path=f"/{maintenance_db}")), kwargs


async def _maintenance_connect(store: "AccountStore", maintenance_db: str):
    """One throwaway driver connection to the server's maintenance database.

    Returns an aiomysql connection (MySQL) or an asyncpg connection
    (Postgres). Kept separate from ``AccountStore.connect`` so the retry
    loop's normal connect path is never involved in DDL.
    """
    if store.backend == "mysql":
        import aiomysql

        p = urlparse(store.database_url)
        try:
            return await aiomysql.connect(
                host=p.hostname or "127.0.0.1",
                port=p.port or 3306,
                user=unquote(p.username or "root"),
                password=unquote(p.password or ""),
                db=None,  # no default database: that is the point
                ssl=_ssl_context(),
                autocommit=True,
                connect_timeout=_MAINTENANCE_CONNECT_TIMEOUT_SECONDS,
            )
        except Exception:
            for fallback_db in ("test", "mysql"):
                try:
                    return await aiomysql.connect(
                        host=p.hostname or "127.0.0.1",
                        port=p.port or 3306,
                        user=unquote(p.username or "root"),
                        password=unquote(p.password or ""),
                        db=fallback_db,
                        ssl=_ssl_context(),
                        autocommit=True,
                        connect_timeout=_MAINTENANCE_CONNECT_TIMEOUT_SECONDS,
                    )
                except Exception:
                    continue
            raise
    import asyncpg

    dsn, kwargs = _pg_maintenance_dsn(store.database_url, maintenance_db)
    return await asyncpg.connect(dsn, timeout=_MAINTENANCE_CONNECT_TIMEOUT_SECONDS, **kwargs)


def _is_already_exists(exc: BaseException) -> bool:
    """True when the server answered "that database already exists".

    Postgres has no CREATE DATABASE IF NOT EXISTS (42P04 duplicate_database),
    MySQL would answer errno 1007 if its IF NOT EXISTS were absent: both mean
    the database is there, which is all the caller wanted.
    """
    if getattr(exc, "sqlstate", None) == "42P04":
        return True
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], int) and args[0] == 1007:
        return True
    return "already exists" in str(exc).lower()


async def _close_quietly(conn) -> None:
    """Close a throwaway connection, sync (aiomysql) or async (asyncpg)."""
    closer = getattr(conn, "close", None)
    if closer is None:
        return
    try:
        result = closer()
        if hasattr(result, "__await__"):
            await result
    except Exception:  # pragma: no cover - closing a leaky connection
        pass




class _PgMigrationIO:
    """The claim protocol (see module header) on one asyncpg connection.

    CockroachDB speaks the same SQL here as Postgres: plain INSERT ... ON
    CONFLICT DO NOTHING, SELECT, UPDATE ... WHERE and DELETE."""

    def __init__(self, conn):
        self._conn = conn

    async def ensure_table(self) -> None:
        await self._conn.execute(_SCHEMA_MIGRATIONS_DDL)

    async def insert_claim(self, version: int, claim_name: str) -> None:
        await self._conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at)"
            " VALUES ($1, $2, NULL) ON CONFLICT (version) DO NOTHING",
            version, claim_name,
        )

    async def read_claim(self, version: int) -> tuple[str | None, str | None] | None:
        row = await self._conn.fetchrow(
            "SELECT name, applied_at FROM schema_migrations WHERE version = $1", version
        )
        return None if row is None else (row["name"], row["applied_at"])

    async def execute(self, sql: str) -> None:
        await self._conn.execute(sql)

    async def finalise(self, version: int, claim_name: str, name: str) -> None:
        await self._conn.execute(
            "UPDATE schema_migrations SET name = $2, applied_at = $3"
            " WHERE version = $1 AND name = $4 AND applied_at IS NULL",
            version, name, _now_iso(), claim_name,
        )

    async def release(self, version: int, claim_name: str) -> None:
        await self._conn.execute(
            "DELETE FROM schema_migrations WHERE version = $1 AND name = $2"
            " AND applied_at IS NULL",
            version, claim_name,
        )

    async def take_over(self, version: int, stale_name: str, claim_name: str) -> None:
        await self._conn.execute(
            "UPDATE schema_migrations SET name = $2"
            " WHERE version = $1 AND name = $3 AND applied_at IS NULL",
            version, claim_name, stale_name,
        )


class _MySqlMigrationIO:
    """The claim protocol on one aiomysql connection. MySQL has no
    ``ON CONFLICT ... DO NOTHING``; ``ON DUPLICATE KEY UPDATE version =
    version`` is its no-op-on-conflict equivalent (a NEW row with an existing
    primary key is refused either way)."""

    def __init__(self, conn):
        self._conn = conn

    async def ensure_table(self) -> None:
        async with self._conn.cursor() as cur:
            await cur.execute(_SCHEMA_MIGRATIONS_DDL, ())

    async def insert_claim(self, version: int, claim_name: str) -> None:
        async with self._conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO schema_migrations (version, name, applied_at)"
                " VALUES (%s, %s, NULL) ON DUPLICATE KEY UPDATE version = version",
                (version, claim_name),
            )

    async def read_claim(self, version: int) -> tuple[str | None, str | None] | None:
        async with self._conn.cursor() as cur:
            await cur.execute(
                "SELECT name, applied_at FROM schema_migrations WHERE version = %s", (version,)
            )
            row = await cur.fetchone()
        return None if row is None else (row[0], row[1])

    async def execute(self, sql: str) -> None:
        async with self._conn.cursor() as cur:
            await cur.execute(sql, ())

    async def finalise(self, version: int, claim_name: str, name: str) -> None:
        async with self._conn.cursor() as cur:
            await cur.execute(
                "UPDATE schema_migrations SET name = %s, applied_at = %s"
                " WHERE version = %s AND name = %s AND applied_at IS NULL",
                (name, _now_iso(), version, claim_name),
            )

    async def release(self, version: int, claim_name: str) -> None:
        async with self._conn.cursor() as cur:
            await cur.execute(
                "DELETE FROM schema_migrations WHERE version = %s AND name = %s"
                " AND applied_at IS NULL",
                (version, claim_name),
            )

    async def take_over(self, version: int, stale_name: str, claim_name: str) -> None:
        async with self._conn.cursor() as cur:
            await cur.execute(
                "UPDATE schema_migrations SET name = %s"
                " WHERE version = %s AND name = %s AND applied_at IS NULL",
                (claim_name, version, stale_name),
            )


class _SqliteMigrationIO:
    """The claim protocol on one sqlite connection inside BEGIN IMMEDIATE.

    The transaction already serialises concurrent starters (a second runner
    blocks on the write lock until the first commits), and sqlite DDL is
    transactional, so a failed or killed run rolls its claim row back with
    everything else. The statements below are local file I/O and complete in
    microseconds; keeping the same async surface lets one runner drive all
    four engines identically."""

    def __init__(self, conn):
        self._conn = conn

    async def ensure_table(self) -> None:
        self._conn.execute(_SCHEMA_MIGRATIONS_DDL)

    async def insert_claim(self, version: int, claim_name: str) -> None:
        self._conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, NULL)"
            " ON CONFLICT(version) DO NOTHING",
            (version, claim_name),
        )

    async def read_claim(self, version: int) -> tuple[str | None, str | None] | None:
        row = self._conn.execute(
            "SELECT name, applied_at FROM schema_migrations WHERE version = ?", (version,)
        ).fetchone()
        return None if row is None else (row[0], row[1])

    async def execute(self, sql: str) -> None:
        self._conn.execute(sql)

    async def finalise(self, version: int, claim_name: str, name: str) -> None:
        self._conn.execute(
            "UPDATE schema_migrations SET name = ?, applied_at = ?"
            " WHERE version = ? AND name = ? AND applied_at IS NULL",
            (name, _now_iso(), version, claim_name),
        )

    async def release(self, version: int, claim_name: str) -> None:
        self._conn.execute(
            "DELETE FROM schema_migrations WHERE version = ? AND name = ? AND applied_at IS NULL",
            (version, claim_name),
        )

    async def take_over(self, version: int, stale_name: str, claim_name: str) -> None:
        self._conn.execute(
            "UPDATE schema_migrations SET name = ?"
            " WHERE version = ? AND name = ? AND applied_at IS NULL",
            (claim_name, version, stale_name),
        )


class AccountStore:
    """Dialect-aware async store. backend in {mysql, postgres, sqlite}."""

    def __init__(self, database_url: str, *, label: str = "primary"):
        self.database_url = database_url
        self.label = label
        parsed = urlparse(database_url)
        scheme = parsed.scheme.lower()
        if scheme in ("mysql", "mariadb"):
            self.backend = "mysql"
        elif scheme in ("postgres", "postgresql"):
            self.backend = "postgres"
        elif scheme == "sqlite":
            self.backend = "sqlite"
        else:
            raise ValueError(
                "DATABASE_URL must use mysql://, mariadb://, postgresql://, "
                "postgres://, or sqlite://"
            )
        self._pg_pool = None
        self._my_pool = None
        self._sqlite_path = ""
        # The database name from the DSN path, parsed once by the same
        # urlparse call that decides the backend.
        raw_db_name = "" if self.backend == "sqlite" else parsed.path.lstrip("/")
        # System catalogs and default placeholders from cloud providers:
        # Many providers (e.g. TiDB Cloud, MySQL RDS) default the connection string
        # to "/sys", "/test", or have no path. Creating user tables in system catalogs
        # is forbidden by MySQL (1142 error). We automatically normalize these to "kxstrel".
        if self.backend in ("mysql", "postgres"):
            system_or_placeholders = (
                "sys", "mysql", "information_schema", "performance_schema",
                "metrics_schema", "test", ""
            )
            if raw_db_name.lower() in system_or_placeholders:
                normalized_db = "kxstrel"
                parsed = parsed._replace(path=f"/{normalized_db}")
                self.database_url = urlunparse(parsed)
                self.database_name = normalized_db
                log.info(
                    "store[%s] DSN referenced placeholder/system database %r; "
                    "automatically normalized to application database %r",
                    self.label, raw_db_name, normalized_db
                )
            else:
                self.database_name = raw_db_name
        else:
            self.database_name = raw_db_name

        if self.backend == "sqlite":
            path = database_url.removeprefix("sqlite:///")
            if path in ("", ":memory:"):
                raise ValueError(
                    "sqlite:///:memory: is not supported because this store "
                    "uses short-lived connections; use sqlite:///path.db"
                )
            self._sqlite_path = path

    def switch_database(self, name: str) -> None:
        """Switch the target database name and rewrite database_url."""
        if self.backend == "sqlite":
            return
        parsed = urlparse(self.database_url)
        parsed = parsed._replace(path=f"/{name}")
        self.database_url = urlunparse(parsed)
        self.database_name = name

    # -- lifecycle ------------------------------------------------------
    async def connect(self) -> None:
        if self.backend == "postgres":
            try:
                import asyncpg
            except ImportError as exc:
                raise RuntimeError("DATABASE_URL is postgres but asyncpg is not installed") from exc
            dsn, kwargs = _pg_dsn_and_tls(self.database_url)
            self._pg_pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5, **kwargs)
            log.info("store[%s] connected backend=postgres", self.label)
        elif self.backend == "mysql":
            try:
                import aiomysql
            except ImportError as exc:
                raise RuntimeError("DATABASE_URL is mysql but aiomysql is not installed") from exc
            p = urlparse(self.database_url)
            self._my_pool = await aiomysql.create_pool(
                host=p.hostname or "127.0.0.1",
                port=p.port or 3306,
                user=unquote(p.username or "root"),
                password=unquote(p.password or ""),
                db=p.path.lstrip("/") or "test",
                ssl=_ssl_context(),
                autocommit=True,
                minsize=1,
                maxsize=5,
                pool_recycle=280,
            )
            log.info("store[%s] connected backend=mysql host=%s", self.label, p.hostname)
        else:
            directory = os.path.dirname(os.path.abspath(self._sqlite_path))
            os.makedirs(directory, exist_ok=True)
            await asyncio.to_thread(self._sqlite_init)
            log.info("store[%s] connected backend=sqlite path=%s", self.label, self._sqlite_path)

    async def close(self) -> None:
        if self._pg_pool is not None:
            await self._pg_pool.close()
            self._pg_pool = None
        if self._my_pool is not None:
            self._my_pool.close()
            await self._my_pool.wait_closed()
            self._my_pool = None

    async def create_database_if_missing(
        self, *, connect=None
    ) -> tuple[bool, BaseException | None]:
        """Best-effort CREATE DATABASE for a DSN whose database is missing.

        Called only when a connection failed *because the database does not
        exist*. Returns ``(created, error)``:

        * ``(True, None)``  — the server accepted it (or it already existed);
        * ``(False, exc)``  — refused by the server / driver failure (typical
          on TiDB with a read-only user and on CockroachDB Serverless, which
          denies CREATE DATABASE); the caller logs it and continues to its
          normal failure path;
        * ``(False, None)`` — creation does not apply (sqlite, or a DSN that
          names no database at all).

        Never raises, never touches the store's own pools, and never logs —
        the caller owns the log line so it can add the classified hint.

        ``connect`` is the injection seam: ``(store, maintenance_db) ->
        connection``, defaulting to the real driver. Tests pass a stub and
        never open a socket.
        """
        if self.backend == "sqlite":
            # A sqlite "database" is a file that connect() itself creates; a
            # missing one means a wrong path, never something to create.
            return False, None
        name = self.database_name
        if not is_plain_identifier(name):
            return False, ValueError(
                "the database name in the DSN is empty or is not a plain identifier"
            )
        statement = create_database_statement(self.backend, name)
        opener = connect or _maintenance_connect
        conn = None
        try:
            conn = await opener(self, _MAINTENANCE_DATABASE[self.backend])
            if self.backend == "mysql":
                async with conn.cursor() as cur:
                    await cur.execute(statement, ())
            else:
                await conn.execute(statement)
        except Exception as exc:
            if _is_already_exists(exc):
                return True, None  # lost a race with the provider/another boot
            return False, exc
        finally:
            if conn is not None:
                await _close_quietly(conn)
        return True, None

    async def init_schema(self) -> None:
        """Versioned, idempotent migrations under one portable atomic claim.

        Every engine takes the same path: claim the version row by primary
        key, run its DDL only if the claim was won, then settle the row (see
        the module header). Nothing here is vendor-specific, so a store whose
        engine lacks advisory locks (CockroachDB) initialises like any other.
        Safe to call concurrently from several instances and repeatedly."""
        if self.backend == "sqlite":
            await self._migrate_sqlite()
            return
        if self.backend == "postgres":
            assert self._pg_pool is not None
            async with self._pg_pool.acquire() as conn:
                await self._apply_migrations(_PgMigrationIO(conn))
            return
        assert self._my_pool is not None
        async with self._my_pool.acquire() as conn:
            await self._apply_migrations(_MySqlMigrationIO(conn))

    # -- migration runner (one connection per backend, inside its claim) --
    async def _migrate_sqlite(self) -> None:
        """BEGIN IMMEDIATE serialises writers on the file: a concurrent
        starter blocks (up to the busy timeout) until this commit, so it
        reads the settled claim instead of racing it. SQLite DDL is
        transactional, so a crash mid-migration rolls the claim back too."""
        conn = self._sqlite_connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            await self._apply_migrations(_SqliteMigrationIO(conn))
            conn.commit()
        except BaseException:
            try:
                conn.rollback()
            except Exception:  # pragma: no cover - rollback is best-effort
                pass
            raise
        finally:
            conn.close()

    async def _apply_migrations(self, io) -> None:
        await io.ensure_table()
        for version, name, statements in _migrations_for(self.backend):
            claim = _claim_marker(name, uuid.uuid4().hex)
            if not await self._claim_version(io, version, claim):
                continue
            try:
                for stmt in statements:
                    for part in self._split_statements(stmt):
                        await io.execute(part)
                await io.finalise(version, claim, name)
            except BaseException:
                # Drop the claim so this version stays unapplied and the next
                # run retries the whole migration: it is never recorded as
                # applied by a run that did not finish.
                try:
                    await io.release(version, claim)
                except Exception as exc:  # pragma: no cover - already failing
                    log.warning("store[%s] could not release the migration %s claim: %s",
                                self.label, version, sanitize_error(str(exc)))
                raise
            log.info("store[%s] migration %s (%s) applied", self.label, version, name)

    async def _claim_version(self, io, version: int, claim: str) -> bool:
        """True when this instance owns ``version``'s claim (and must run its
        DDL). False when another instance already applied it.

        A claim that never settles means its owner died mid-DDL; after
        ``_MIGRATION_CLAIM_WAIT_SECONDS`` the claim is taken over with a
        compare-and-swap on the token and the migration is retried."""
        deadline = time.monotonic() + _MIGRATION_CLAIM_WAIT_SECONDS
        while True:
            await io.insert_claim(version, claim)
            row = await io.read_claim(version)
            if row is not None and row[0] == claim:
                return True  # the primary key let exactly one instance in
            if row is not None and row[1] is not None:
                return False  # applied by another instance
            if time.monotonic() < deadline:
                await asyncio.sleep(_MIGRATION_CLAIM_POLL_SECONDS)
                continue
            if row is not None:
                stale = row[0]
                await io.take_over(version, stale, claim)
                taken = await io.read_claim(version)
                if taken is not None and taken[0] == claim:
                    log.warning(
                        "store[%s] migration %s claim from %s looks abandoned; retrying it",
                        self.label, version, stale,
                    )
                    return True
            raise RuntimeError(
                f"could not claim migration {version} within "
                f"{_MIGRATION_CLAIM_WAIT_SECONDS:.0f}s; another instance may be migrating"
            )

    async def ping(self) -> bool:
        try:
            await self._fetch_one("SELECT 1 AS one")
            return True
        except Exception as exc:
            log.warning("store[%s] ping failed: %s", self.label, sanitize_error(str(exc)))
            return False

    # -- sqlite helpers ---------------------------------------------------
    def _sqlite_connect(self) -> sqlite3.Connection:
        """One short-lived connection with a busy timeout (so a concurrent
        writer waits instead of failing) and dict-like rows."""
        conn = sqlite3.connect(self._sqlite_path, timeout=_SQLITE_BUSY_TIMEOUT_SECONDS)
        conn.row_factory = sqlite3.Row
        return conn

    def _sqlite_init(self) -> None:
        conn = self._sqlite_connect()
        try:
            conn.execute("SELECT 1")
        finally:
            conn.close()

    def _sqlite_exec(self, sql: str, params: tuple = (), fetch: str = "none"):
        # sqlite3's context manager commits but never closes: close it here so
        # long-running processes do not leak a file descriptor per statement.
        conn = self._sqlite_connect()
        try:
            cur = conn.execute(sql, params)
            if fetch == "all":
                return [dict(r) for r in cur.fetchall()]
            if fetch == "one":
                row = cur.fetchone()
                return dict(row) if row else None
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()

    # -- query plumbing -----------------------------------------------------
    @staticmethod
    def _pg(sql: str) -> str:
        """qmark -> $n, ignoring `?` inside literals/comments/identifiers.

        Postgres literals are standard SQL: a backslash is an ordinary
        character, so the scanner must not treat it as an escape."""
        out, idx = [], 0
        for chunk, is_code in _scan_sql(sql):
            if is_code and chunk == "?":
                idx += 1
                out.append(f"${idx}")
            else:
                out.append(chunk)
        return "".join(out)

    @staticmethod
    def _mysql_prepare(sql: str, params: tuple) -> tuple[str, tuple | None]:
        """aiomysql/pymysql speaks %s paramstyle: convert qmark and escape
        literal % only when args are actually interpolated."""
        if not params:
            return sql, None
        return sql.replace("%", "%%").replace("?", "%s"), params

    def _split_statements(self, sql: str, params: tuple = ()) -> list[str]:
        """Split on `;` outside literals/comments only. Parameterized SQL
        must be a single statement: executing one param tuple against several
        statements would silently bind the wrong values."""
        parts: list[str] = []
        buf: list[str] = []
        for chunk, is_code in _scan_sql(sql, backslash_escapes=self.backend == "mysql"):
            if is_code and chunk == ";":
                parts.append("".join(buf))
                buf = []
            else:
                buf.append(chunk)
        parts.append("".join(buf))
        statements = [s.strip() for s in parts if s.strip()]
        if params and len(statements) > 1:
            raise ValueError(
                "parameterized SQL must be a single statement; got "
                f"{len(statements)} statements. Split and execute them "
                "separately or inline the constants."
            )
        return statements

    async def _fetch_all(self, sql: str, params: tuple = ()):
        if self.backend == "postgres":
            assert self._pg_pool is not None
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(self._pg(sql), *params)
                return [dict(r) for r in rows]
        if self.backend == "mysql":
            import aiomysql

            assert self._my_pool is not None
            my_sql, my_args = self._mysql_prepare(sql, params)
            async with self._my_pool.acquire() as conn:
                async with conn.cursor(aiomysql.DictCursor) as cur:
                    await cur.execute(my_sql, my_args or ())
                    return [dict(r) for r in await cur.fetchall()]
        return await asyncio.to_thread(self._sqlite_exec, sql, params, "all")

    async def _fetch_one(self, sql: str, params: tuple = ()):
        rows = await self._fetch_all(sql + (" LIMIT 1" if "LIMIT" not in sql.upper() else ""), params)
        return rows[0] if rows else None

    async def _exec(self, sql: str, params: tuple = ()):
        statements = self._split_statements(sql, params)
        if self.backend == "postgres":
            assert self._pg_pool is not None
            async with self._pg_pool.acquire() as conn:
                for stmt in statements:
                    # Every rewritten $n needs its argument: dropping *params
                    # here turns any parameterized write into a driver error
                    # (asyncpg: "expected N arguments"). _split_statements has
                    # already refused multi-statement SQL when params is set.
                    await conn.execute(self._pg(stmt), *params)
        elif self.backend == "mysql":
            assert self._my_pool is not None
            my_sql, my_args = self._mysql_prepare(sql, params)
            async with self._my_pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(my_sql, my_args or ())
        else:
            for stmt in statements:
                await asyncio.to_thread(self._sqlite_exec, stmt, params, "none")

    # ── accounts (multi-account ready) ─────────────────────────────────
    async def upsert_account(
        self, label: str, enc_auth_token: str, enc_ct0: str, enabled: bool = True, meta: str = "{}"
    ) -> None:
        now = _now_iso()
        base = """
        INSERT INTO x_accounts
            (label, enc_auth_token, enc_ct0, enabled, status, meta, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'NOT_CONFIGURED', ?, ?, ?)
        """
        if self.backend == "mysql":
            sql = base + """ ON DUPLICATE KEY UPDATE
                enc_auth_token=VALUES(enc_auth_token), enc_ct0=VALUES(enc_ct0),
                enabled=VALUES(enabled), meta=VALUES(meta), updated_at=VALUES(updated_at)"""
        else:
            conflict = "ON CONFLICT (label)" if self.backend == "postgres" else "ON CONFLICT(label)"
            sql = base + f""" {conflict} DO UPDATE SET
                enc_auth_token=excluded.enc_auth_token, enc_ct0=excluded.enc_ct0,
                enabled=excluded.enabled, meta=excluded.meta, updated_at=excluded.updated_at"""
        await self._exec(sql, (label, enc_auth_token, enc_ct0, int(enabled), meta or "{}", now, now))

    async def set_account_enabled(self, label: str, enabled: bool) -> bool:
        return await self.update_field("x_accounts", label, "enabled", int(enabled))

    async def is_account_enabled(self, label: str) -> bool:
        row = await self._fetch_one("SELECT enabled FROM x_accounts WHERE label = ?", (label,))
        return bool(row["enabled"]) if row else False

    # Allowlisted targeted updates: (table, field) pairs are code-controlled
    # constants; anything else is a programming error, never user input.
    _UPDATEABLE_FIELDS = frozenset({("x_accounts", "enabled")})

    async def update_field(self, table: str, label: str, field: str, value) -> bool:
        if (table, field) not in self._UPDATEABLE_FIELDS:
            raise ValueError(f"update_field not allowed for ({table}, {field})")
        rows = await self._fetch_all(f"SELECT label FROM {table} WHERE label = ?", (label,))
        if not rows:
            return False
        await self._exec(
            f"UPDATE {table} SET {field} = ?, updated_at = ? WHERE label = ?",
            (value, _now_iso(), label),
        )
        return True

    async def get_enabled_accounts(self) -> list[AccountRecord]:
        rows = await self._fetch_all(
            "SELECT * FROM x_accounts WHERE enabled = 1 ORDER BY label ASC"
        )
        return [_row_to_record(r) for r in rows]

    async def get_all_accounts(self) -> list[AccountRecord]:
        rows = await self._fetch_all("SELECT * FROM x_accounts ORDER BY label ASC")
        return [_row_to_record(r) for r in rows]

    async def list_accounts_meta(self) -> list[dict]:
        """Redacted listing for admin/status surfaces. Never includes ciphertext."""
        rows = await self._fetch_all(
            "SELECT label, enabled, status, last_checked_at, last_check_ok,"
            " last_error, created_at, updated_at FROM x_accounts ORDER BY label ASC"
        )
        out = []
        for d in rows:
            d["enabled"] = bool(d["enabled"])
            if d.get("last_check_ok") is not None:
                d["last_check_ok"] = bool(d["last_check_ok"])
            out.append(d)
        return out

    async def update_status(self, label: str, status: str, ok: bool | None, error: str | None) -> None:
        await self._exec(
            "UPDATE x_accounts SET status=?, last_checked_at=?, last_check_ok=?,"
            " last_error=?, updated_at=? WHERE label=?",
            (status, _now_iso(), None if ok is None else int(ok), error, _now_iso(), label),
        )

    async def delete_account(self, label: str) -> bool:
        rows = await self._fetch_all("SELECT label FROM x_accounts WHERE label = ?", (label,))
        if not rows:
            return False
        await self._exec("DELETE FROM x_accounts WHERE label = ?", (label,))
        return True

    # ── tool flags (enable/disable per tool via admin UI) ─────────────
    async def get_tool_flag(self, tool_name: str) -> bool:
        row = await self._fetch_one(
            "SELECT enabled FROM tool_flags WHERE tool_name = ?", (tool_name,)
        )
        return bool(row["enabled"]) if row else True  # default: enabled

    async def set_tool_flag(self, tool_name: str, enabled: bool) -> None:
        sql_conflict = ("ON DUPLICATE KEY UPDATE enabled=VALUES(enabled), updated_at=VALUES(updated_at)"
                        if self.backend == "mysql" else
                        "ON CONFLICT(tool_name) DO UPDATE SET enabled=excluded.enabled, updated_at=excluded.updated_at")
        await self._exec(
            f"INSERT INTO tool_flags (tool_name, enabled, updated_at) VALUES (?, ?, ?) {sql_conflict}",
            (tool_name, int(enabled), _now_iso()),
        )

    async def list_tool_flags(self) -> dict[str, bool]:
        rows = await self._fetch_all("SELECT tool_name, enabled FROM tool_flags")
        return {r["tool_name"]: bool(r["enabled"]) for r in rows}

    # ── usage logs ─────────────────────────────────────────────────────
    async def log_tool_usage(self, tool_name: str, ok: bool, error: str | None,
                             duration_ms: int, caller: str | None) -> None:
        # tool_name comes from the wire and may be arbitrary (nonexistent
        # tool calls are logged before resolution) — cap it at column width.
        await self._exec(
            "INSERT INTO tool_usage (ts, tool_name, ok, error, duration_ms, caller_fp)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (_now_iso(), tool_name[:128], int(ok),
             sanitize_error(error or "")[:300] or None, int(duration_ms), caller),
        )

    async def list_tool_usage(self, limit: int = 50, offset: int = 0,
                              tool: str | None = None, ok: bool | None = None) -> list[dict]:
        where, params = ["1=1"], []
        if tool:
            where.append("tool_name = ?")
            params.append(tool)
        if ok is not None:
            where.append("ok = ?")
            params.append(int(ok))
        rows = await self._fetch_all(
            f"SELECT ts, tool_name, ok, error, duration_ms, caller_fp FROM tool_usage"
            f" WHERE {' AND '.join(where)} ORDER BY ts DESC LIMIT ? OFFSET ?",
            (*params, int(limit), int(offset)),
        )
        for r in rows:
            r["ok"] = bool(r["ok"])
        return rows

    async def count_tool_usage(self, tool: str | None = None, ok: bool | None = None) -> int:
        where, params = ["1=1"], []
        if tool:
            where.append("tool_name = ?")
            params.append(tool)
        if ok is not None:
            where.append("ok = ?")
            params.append(int(ok))
        row = await self._fetch_one(
            f"SELECT COUNT(*) AS n FROM tool_usage WHERE {' AND '.join(where)}", tuple(params)
        )
        return int(row["n"]) if row else 0

    async def usage_summary(self, days: int = 7) -> dict:
        cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
        cutoff_iso = datetime.fromtimestamp(cutoff, tz=timezone.utc).isoformat()
        total = await self._fetch_one(
            "SELECT COUNT(*) AS n, SUM(ok) AS okn FROM tool_usage WHERE ts >= ?", (cutoff_iso,)
        )
        top = await self._fetch_all(
            "SELECT tool_name, COUNT(*) AS calls FROM tool_usage WHERE ts >= ?"
            " GROUP BY tool_name ORDER BY calls DESC LIMIT 10", (cutoff_iso,)
        )
        return {
            "days": days,
            "total": int(total["n"] or 0) if total else 0,
            "ok": int(total["okn"] or 0) if total else 0,
            "top_tools": top,
        }

    async def prune_tool_usage(self, retention_days: int) -> int:
        cutoff = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() - retention_days * 86400, tz=timezone.utc
        ).isoformat()
        if self.backend == "mysql":
            before = await self.count_tool_usage()
            await self._exec("DELETE FROM tool_usage WHERE ts < ?", (cutoff,))
            return before
        count = await asyncio.to_thread(
            self._sqlite_exec, "DELETE FROM tool_usage WHERE ts < ?", (cutoff,), "none"
        ) if self.backend == "sqlite" else None
        if count is not None:
            return int(count)
        before = await self.count_tool_usage()
        await self._exec("DELETE FROM tool_usage WHERE ts < ?", (cutoff,))
        return before

    # ── admin audit ────────────────────────────────────────────────────
    async def log_admin_action(self, action: str, detail: str | None, request_id: str | None) -> None:
        await self._exec(
            "INSERT INTO admin_audit (ts, action, detail, request_id) VALUES (?, ?, ?, ?)",
            (_now_iso(), action, sanitize_error(detail or "")[:500] or None, request_id),
        )

    async def list_admin_audit(self, limit: int = 50, offset: int = 0) -> list[dict]:
        return await self._fetch_all(
            "SELECT ts, action, detail, request_id FROM admin_audit"
            " ORDER BY ts DESC LIMIT ? OFFSET ?", (int(limit), int(offset))
        )

    # ── meta (persisted uptime markers etc.) ────────────────────────────
    async def get_meta(self, key: str) -> str | None:
        row = await self._fetch_one("SELECT v FROM meta WHERE k = ?", (key,))
        return row["v"] if row and row.get("v") else None

    async def set_meta(self, key: str, value: str) -> None:
        if self.backend == "mysql":
            sql = ("INSERT INTO meta (k, v, updated_at) VALUES (?, ?, ?) "
                   "ON DUPLICATE KEY UPDATE v=VALUES(v), updated_at=VALUES(updated_at)")
        else:
            conflict = ("ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at"
                        if self.backend == "postgres" else
                        "ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at")
            sql = f"INSERT INTO meta (k, v, updated_at) VALUES (?, ?, ?) {conflict}"
        await self._exec(sql, (key, value, _now_iso()))

    # ── raw row access for backup ──────────────────────────────────────
    async def dump_accounts(self) -> list[dict]:
        return await self._fetch_all("SELECT * FROM x_accounts ORDER BY label")

    async def dump_schema_migrations(self) -> list[dict]:
        return await self._fetch_all(
            "SELECT version, name, applied_at FROM schema_migrations ORDER BY version"
        )

    async def dump_tool_flags(self) -> list[dict]:
        return await self._fetch_all("SELECT * FROM tool_flags ORDER BY tool_name")

    async def dump_admin_audit(self) -> list[dict]:
        return await self._fetch_all("SELECT * FROM admin_audit ORDER BY ts")
