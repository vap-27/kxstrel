"""Resilient store startup: bounded retry, error classification, hints.

A database connection is the one dependency whose failure must be neither
fatal nor silent. It used to be both: one connect attempt, one opaque
warning, and a gateway that kept running with no store. A cold network, a
TLS hiccup or a serverless database waking up all looked identical.

This module wraps ``AccountStore.connect()`` + ``init_schema()`` for the
primary AND the backup store with:

* a bounded retry — the first attempt is immediate, then the delay doubles
  per failed attempt, is capped by ``DB_CONNECT_MAX_DELAY_SECONDS`` and
  jittered, and every sleep is ``asyncio.sleep`` (never blocking the event
  loop). The total wait is bounded by the attempt count, so a degraded start
  stays a degraded start instead of becoming a hang;
* ``classify_db_error``: a closed set of failure kinds plus a one-line hint
  naming the concrete thing to check, surfaced in the startup log and in
  GET /diagnostics;
* a best-effort ``CREATE DATABASE`` when the ONLY problem is that the
  database does not exist yet (MySQL/Postgres; see db.create_database_if_missing).

Nothing here raises: the caller gets a ``ConnectOutcome`` and decides what a
failure means for its own degraded-mode behaviour. Nothing here logs or
returns the DSN, a password, or a raw driver dump.
"""

from __future__ import annotations

import asyncio
import random
import socket
import ssl
import time
from dataclasses import dataclass, field

from .logging_setup import get_logger, sanitize_error

log = get_logger("kxstrel-x-mcp.db")

# ── failure classification ───────────────────────────────────────────────
#
# One closed set of kinds. Every hint is a static sentence naming the thing
# to check — it can therefore never contain a password or the DSN, however
# weird the driver's message is. The raw message is logged separately and
# always through sanitize_error().

DB_ERROR_KINDS = frozenset({
    "unsupported_dsn",
    "driver_missing",
    "host_unreachable",
    "timeout",
    "auth_failed",
    "unknown_database",
    "tls_error",
    "too_many_connections",
    "unknown",
})

ERROR_HINTS: dict[str, str] = {
    "unsupported_dsn": (
        "DATABASE_URL must be mysql://, mariadb://, postgres://, "
        "postgresql:// or sqlite:// with a file path; check the scheme and path"
    ),
    "driver_missing": (
        "the driver for this backend is not installed in the running "
        "environment; install asyncpg (postgres) or aiomysql (mysql)"
    ),
    "host_unreachable": (
        "the database host could not be resolved or reached; check the "
        "host/port in the DSN, DNS, and network/firewall rules from here"
    ),
    "timeout": (
        "the connection timed out; the database may be waking up, "
        "overloaded or unreachable from this network: check its status"
    ),
    "auth_failed": (
        "the server denied the login; check the DSN username/password and "
        "that this user may connect from this host"
    ),
    "unknown_database": (
        "the database named in the DSN does not exist; create it in the "
        "provider console (or let the gateway try) and check the DSN path"
    ),
    "tls_error": (
        "the TLS handshake or certificate verification failed; check "
        "sslmode/certs and that the server presents a trusted certificate"
    ),
    "too_many_connections": (
        "the server refused the connection because its connection limit is "
        "reached; close other clients or raise the limit"
    ),
    "unknown": (
        "the failure did not match a known category; read the sanitized "
        "driver message above and check connectivity to the database"
    ),
}

# SQLSTATE (postgres family, incl. CockroachDB) -> kind.
_SQLSTATE_KINDS = {
    "28P01": "auth_failed",              # invalid_password
    "28000": "auth_failed",              # invalid_authorization_specification
    "42501": "auth_failed",              # insufficient_privilege
    "3D000": "unknown_database",         # invalid_catalog_name
    "53300": "too_many_connections",     # too_many_connections
    "08000": "host_unreachable",         # connection_exception
    "08001": "host_unreachable",         # sqlclient_unable_to_establish_sqlconnection
    "08003": "host_unreachable",         # connection_does_not_exist
    "08004": "host_unreachable",         # sqlserver_rejected_establishment_of_sqlconnection
    "08006": "host_unreachable",         # connection_failure
    "08007": "host_unreachable",         # transaction_resolution_unknown
    "57P03": "host_unreachable",         # cannot_connect_now (server starting)
}

# MySQL client/server errno -> kind (pymysql/aiomysql args[0]).
_MYSQL_ERRNO_KINDS = {
    1040: "too_many_connections",        # too many connections
    1203: "too_many_connections",        # too many user connections
    1044: "auth_failed",                 # access denied for user to database
    1045: "auth_failed",                 # access denied (bad credentials)
    1142: "auth_failed",                 # command denied
    1143: "auth_failed",                 # select denied
    1049: "unknown_database",            # unknown database
    1007: "unknown_database",            # database exists (creation race)
    2001: "host_unreachable",            # unknown host
    2002: "host_unreachable",            # can't connect to local server
    2003: "host_unreachable",            # can't connect to server
    2005: "host_unreachable",            # unknown host
    2006: "host_unreachable",            # server has gone away
    2013: "host_unreachable",            # lost connection during query
    2026: "tls_error",                   # SSL connection error
    3159: "tls_error",                   # insecure transport prohibited
}

# errno -> kind. Both the POSIX and the Windows (WSA*) spellings are listed:
# the same failure carries different numbers depending on the platform the
# gateway runs on, and the classification must not depend on that.
_NET_ERRNO_KINDS = {
    111: "host_unreachable",    # POSIX ECONNREFUSED
    101: "host_unreachable",    # POSIX ENETUNREACH
    113: "host_unreachable",    # POSIX EHOSTUNREACH
    112: "host_unreachable",    # POSIX EHOSTDOWN
    100: "host_unreachable",    # POSIX ENETDOWN
    110: "timeout",             # POSIX ETIMEDOUT
    10061: "host_unreachable",  # WSAECONNREFUSED
    10051: "host_unreachable",  # WSAENETUNREACH
    10065: "host_unreachable",  # WSAEHOSTUNREACH
    10064: "host_unreachable",  # WSAEHOSTDOWN
    10050: "host_unreachable",  # WSAENETDOWN
    11001: "host_unreachable",  # WSAHOST_NOT_FOUND
    11002: "host_unreachable",  # WSATRY_AGAIN
    10060: "timeout",           # WSAETIMEDOUT
}

# TLS text needles. Deliberately specific: a DSN that merely carries
# "?sslmode=..." inside an error message must NOT be read as a TLS failure.
_TLS_NEEDLES = (
    "certificate",
    "ssl handshake",
    "tls handshake",
    "ssl connection",
    "ssl error",
    "ssl:",
    "ssl is required",
)

# Message-text fallbacks, matched in order. Only consulted when no code
# matched; the text itself is never returned to a caller.
_TEXT_KINDS: tuple[tuple[str, str], ...] = (
    ("unknown database", "unknown_database"),
    ("no such database", "unknown_database"),
    ("access denied", "auth_failed"),
    ("authentication failed", "auth_failed"),
    ("password authentication failed", "auth_failed"),
    ("permission denied", "auth_failed"),
    ("too many connections", "too_many_connections"),
    ("name or service not known", "host_unreachable"),
    ("nodename nor servname", "host_unreachable"),
    ("getaddrinfo", "host_unreachable"),
    ("unknown host", "host_unreachable"),
    ("connection refused", "host_unreachable"),
    ("can't connect", "host_unreachable"),
    ("cannot connect", "host_unreachable"),
    ("server has gone away", "host_unreachable"),
    ("certificate verify failed", "tls_error"),
    ("timed out", "timeout"),
)

# Checked before anything else: they describe the configuration, not the
# network, and their text can look like one of the patterns above. The local
# file entries are how a bad sqlite path (or an unwritable directory) is
# classified: a DSN whose path cannot be opened is a DSN to fix, not a
# connectivity incident.
_CONFIG_KINDS: tuple[tuple[str, str], ...] = (
    ("not installed", "driver_missing"),
    ("no module named", "driver_missing"),
    ("must use mysql", "unsupported_dsn"),
    ("is not supported", "unsupported_dsn"),
    ("unsupported dsn", "unsupported_dsn"),
    ("invalid dsn", "unsupported_dsn"),
    ("invalid url", "unsupported_dsn"),
    ("unable to open database file", "unsupported_dsn"),
    ("is a directory", "unsupported_dsn"),
    ("file exists", "unsupported_dsn"),
    ("cannot create a file when that file already exists", "unsupported_dsn"),
    ("cannot find the path specified", "unsupported_dsn"),
    ("readonly database", "unsupported_dsn"),
)


def _text_of(exc: BaseException) -> str:
    try:
        return f"{type(exc).__name__}: {exc}".lower()
    except Exception:  # pragma: no cover - a __str__ that throws
        return type(exc).__name__.lower()


def _mysql_errno(exc: BaseException) -> int | None:
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], int) and not isinstance(args[0], bool):
        return args[0]
    return None


def _classify_kind(exc: BaseException) -> str:
    if not isinstance(exc, BaseException):  # defensive: a stubbed 'error'
        return "unknown"
    text = _text_of(exc)
    name = type(exc).__name__.lower()

    # TLS first: ssl.SSLError is an OSError, and "certificate" text can also
    # appear in a pymysql message that a generic network check would steal.
    if (isinstance(exc, ssl.SSLError) or "ssl" in name
            or any(needle in text for needle in _TLS_NEEDLES)):
        return "tls_error"
    for needle, kind in _CONFIG_KINDS:
        if needle in text:
            return kind

    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)) or "timeout" in name:
        return "timeout"

    sqlstate = getattr(exc, "sqlstate", None)
    if isinstance(sqlstate, str) and sqlstate in _SQLSTATE_KINDS:
        return _SQLSTATE_KINDS[sqlstate]

    errno = _mysql_errno(exc)
    if errno is not None and errno in _MYSQL_ERRNO_KINDS:
        return _MYSQL_ERRNO_KINDS[errno]

    if isinstance(exc, socket.gaierror):        # DNS: unknown host
        return "host_unreachable"
    if isinstance(exc, ConnectionError):        # refused / reset / aborted
        return "host_unreachable"
    if isinstance(exc, OSError):
        kind = _NET_ERRNO_KINDS.get(getattr(exc, "errno", None) or 0)
        if kind:
            return kind

    if "timeout" in text or "timed out" in text:
        return "timeout"
    # "... does not exist" only means a missing database when it is about a
    # database; "role does not exist" is an auth problem.
    if "does not exist" in text:
        return "unknown_database" if "database" in text else "auth_failed"
    for needle, kind in _TEXT_KINDS:
        if needle in text:
            return kind
    return "unknown"


def classify_db_error(exc: BaseException) -> tuple[str, str]:
    """``(kind, hint)`` for a failed store connection.

    ``kind`` is one of ``DB_ERROR_KINDS``; ``hint`` is a static, actionable
    sentence naming the concrete thing to check. Neither is derived from the
    driver's message text, so neither can carry a credential or the DSN.
    """
    kind = _classify_kind(exc)
    return kind, ERROR_HINTS[kind]


# ── bounded retry ────────────────────────────────────────────────────────

# Hard ceilings on the operator-supplied policy: a misconfigured .env must
# not be able to turn a degraded start into an unbounded one.
_MAX_ATTEMPTS_CEILING = 10
_MAX_DELAY_CEILING_SECONDS = 60.0
# One attempt's connect() is bounded; init_schema() is not, because it has
# its own bounded claim wait (_MIGRATION_CLAIM_WAIT_SECONDS) and killing it
# would make two instances booting together fight over the claim.
_CONNECT_TIMEOUT_SECONDS = 30.0

# Injection seams: tests replace these (or pass sleep=/rand=) so no test
# ever waits on a real clock.
_SLEEP = asyncio.sleep
_RAND = random.random
_MONOTONIC = time.monotonic


@dataclass
class ConnectOutcome:
    """What happened to connect() + init_schema() for one store."""

    ok: bool
    attempts: int = 0
    error_kind: str | None = None
    hint: str | None = None
    message: str | None = None       # sanitized; never the DSN
    elapsed_seconds: float = 0.0
    database_created: bool = False
    delays: list[float] = field(default_factory=list)


def _policy(settings) -> tuple[int, float, float]:
    """``(max_attempts, base_delay, max_delay)`` from settings, clamped."""
    attempts = int(getattr(settings, "DB_CONNECT_MAX_ATTEMPTS", 5) or 1)
    attempts = max(1, min(attempts, _MAX_ATTEMPTS_CEILING))
    base = float(getattr(settings, "DB_CONNECT_BASE_DELAY_SECONDS", 1.0) or 0.0)
    cap = float(getattr(settings, "DB_CONNECT_MAX_DELAY_SECONDS", 15.0) or 0.0)
    base = max(0.0, min(base, _MAX_DELAY_CEILING_SECONDS))
    cap = max(0.0, min(cap, _MAX_DELAY_CEILING_SECONDS))
    return attempts, base, cap


def backoff_delay(failed_attempt: int, base: float, cap: float, rand=None) -> float:
    """Delay before attempt ``failed_attempt + 1``: capped exponential plus
    up to 100% jitter (full jitter on the capped value, so the ceiling is
    never exceeded)."""
    rand = _RAND if rand is None else rand
    if base <= 0.0 or cap <= 0.0:
        return 0.0
    delay = min(base * (2 ** max(0, failed_attempt - 1)), cap)
    return delay * rand()


async def _close_quietly(store) -> None:
    """Drop any half-open pool before the next attempt, best effort."""
    try:
        await store.close()
    except Exception as exc:  # pragma: no cover - already failing
        log.debug("store close during retry failed: %s", sanitize_error(str(exc)))


async def connect_and_init(store, settings, *, sleep=None, rand=None,
                           timeout: float | None = None) -> ConnectOutcome:
    """Connect a store and run its schema migrations, with bounded retry.

    ``sleep`` / ``rand`` / ``timeout`` are injection seams (tests never wait
    on a real clock). Returns a ``ConnectOutcome``; it never raises, so a
    caller always reaches its own degraded-mode path.
    """
    sleep = _SLEEP if sleep is None else sleep
    rand = _RAND if rand is None else rand
    connect_timeout = _CONNECT_TIMEOUT_SECONDS if timeout is None else timeout
    max_attempts, base, cap = _policy(settings)
    label = getattr(store, "label", "primary")
    started = _MONOTONIC()
    outcome = ConnectOutcome(ok=False)

    creation_attempted = False
    for attempt in range(1, max_attempts + 1):
        outcome.attempts = attempt
        try:
            await asyncio.wait_for(store.connect(), timeout=connect_timeout)
            await store.init_schema()
        except Exception as exc:
            kind, hint = classify_db_error(exc)
            outcome.error_kind, outcome.hint = kind, hint
            outcome.message = sanitize_error(f"{type(exc).__name__}: {exc}")
            # A half-open pool must not survive into the next attempt.
            await _close_quietly(store)
            log.warning("store[%s] connect attempt %d/%d failed kind=%s: %s",
                        label, attempt, max_attempts, kind, outcome.message)
            if kind == "unsupported_dsn":
                # Configuration, not transience: retrying cannot help.
                break
            if kind == "unknown_database" and not creation_attempted:
                creation_attempted = True
                created = await _try_create_database(store, label)
                if created:
                    outcome.database_created = True
                    continue  # the database now exists: retry immediately
            if attempt >= max_attempts:
                break
            delay = backoff_delay(attempt, base, cap, rand)
            outcome.delays.append(delay)
            log.info("store[%s] retrying in %.1fs (attempt %d/%d, kind=%s)",
                     label, delay, attempt + 1, max_attempts, kind)
            await sleep(delay)
            continue
        outcome.ok = True
        outcome.error_kind = None
        outcome.hint = None
        outcome.message = None
        outcome.elapsed_seconds = _MONOTONIC() - started
        log.info("store[%s] ready after %d attempt(s) in %.1fs",
                 label, attempt, outcome.elapsed_seconds)
        return outcome

    outcome.elapsed_seconds = _MONOTONIC() - started
    if outcome.error_kind is None:  # pragma: no cover - loop always sets it
        outcome.error_kind = "unknown"
        outcome.hint = ERROR_HINTS["unknown"]
        outcome.message = "no connection attempt was made"
    log.error("store[%s] unavailable after %d attempt(s) in %.1fs: kind=%s (%s); hint: %s",
              label, outcome.attempts, outcome.elapsed_seconds,
              outcome.error_kind, outcome.message, outcome.hint)
    return outcome


async def _try_create_database(store, label: str) -> bool:
    """Best-effort CREATE DATABASE with an actionable log line either way."""
    created, error = await store.create_database_if_missing()
    if created:
        log.info("store[%s] created the missing database %r and will retry",
                 label, getattr(store, "database_name", ""))
        return True
    if error is None:
        # sqlite, or a DSN naming no database: nothing to create, and a retry
        # will fail identically. Say so rather than looping silently.
        log.warning("store[%s] database is missing and cannot be auto-created "
                    "from this DSN; create it manually and restart", label)
        return False
    kind, hint = classify_db_error(error)
    log.warning(
        "store[%s] could not create the missing database (%s): %s; hint: %s. "
        "Create it once in the provider console (TiDB Cloud and CockroachDB "
        "Serverless normally deny CREATE DATABASE) or point the DSN at an "
        "existing database",
        label, kind, sanitize_error(f"{type(error).__name__}: {error}"), hint,
    )
    return False
