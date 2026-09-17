"""Environment-driven configuration. No secrets are hard-coded; everything
comes from the environment (or a local .env file for development).

Secret strength: bearer/admin tokens must be at least MIN_SECRET_LENGTH
characters (see ``secret_strength_problems``); startup refuses obviously
weak values instead of silently accepting a guessable token. Empty values
are allowed — they mean "not configured" and the auth layer already answers
503 for those surfaces."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

# Minimum length for MCP_ACCESS_TOKEN / ADMIN_TOKEN / CREDENTIAL_ENCRYPTION_KEY.
# 32 chars of urlsafe base64 ≈ 192 bits of entropy from a CSPRNG, which is the
# documented generation recipe (`secrets.token_urlsafe(32)`).
MIN_SECRET_LENGTH = 32

_GENERATE_HINT = (
    'generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- gateway identity -------------------------------------------------
    APP_NAME: str = "Kxstrel X MCP"

    # --- client authentication -------------------------------------------
    # Bearer token remote MCP clients must present. Never the X cookies.
    MCP_ACCESS_TOKEN: str = ""
    # Separate secret guarding /admin/* credential-management endpoints.
    ADMIN_TOKEN: str = ""

    # --- persistence ------------------------------------------------------
    # Primary store: TiDB (MySQL), Postgres, or sqlite file (local dev).
    # Examples:
    #   mysql://user:pass@host:4000/db          (TiDB - 5GB free tier)
    #   postgresql://user:pass@host:5432/db     (Render Postgres)
    #   sqlite:///./data/kxstrel.db                (local dev only)
    DATABASE_URL: str = "sqlite:///./data/kxstrel.db"
    # Optional backup store (Postgres-compatible, e.g. CockroachDB 10GB free).
    # Every run appends a new snapshot (accounts / schema_migrations / tool
    # flags / admin audit); snapshots older than BACKUP_RETENTION_DAYS are
    # pruned after each successful run.
    BACKUP_DATABASE_URL: str = ""
    # Fernet key (urlsafe base64, 32 bytes) used to encrypt auth_token/ct0.
    # Generate: python scripts/setup_account.py --generate-key
    CREDENTIAL_ENCRYPTION_KEY: str = ""
    # Startup connect + schema init retry policy, for the primary AND the
    # backup store. A transient failure (cold network, TLS hiccup, a
    # serverless database waking up) must not leave the gateway storeless.
    # Attempts are bounded, delays are exponential and capped, the first
    # attempt is immediate, and a failure never blocks startup (the existing
    # degraded-mode fallbacks still apply).
    DB_CONNECT_MAX_ATTEMPTS: int = 5
    DB_CONNECT_BASE_DELAY_SECONDS: float = 1.0
    DB_CONNECT_MAX_DELAY_SECONDS: float = 15.0

    # --- optional Redis -----------------------------------------------------
    # Enables shared admin-UI sessions across instances. Everything works
    # without it (single instance), so this stays optional.
    REDIS_URL: str = ""

    # --- networking -------------------------------------------------------
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ALLOWED_ORIGINS: str = "*"
    # Optional, NON-secret: the origin this gateway advertises to clients
    # (401 `resource_metadata` challenges, protected-resource metadata), e.g.
    # https://x-mcp.onrender.com. When set it is authoritative and the
    # client-supplied Host / X-Forwarded-Host headers are ignored, which is
    # the only way to make the advertised origin unconditionally trustworthy.
    # Schemeless, pathed or otherwise malformed values are rejected and the
    # request-derived origin is used instead (see app/security.py).
    PUBLIC_BASE_URL: str = ""

    # --- local account pool cache -----------------------------------------
    # The local sqlite pool file (kxstrel-accs.db) is only an ephemeral cache:
    # the primary DB is the source of truth and the pool is rebuilt from it
    # on every startup, so losing this file is harmless.
    SPECTRE_DB_PATH: str = "./data/kxstrel-accs.db"
    KXSTREL_DB_PATH: str = ""

    # --- session health ----------------------------------------------------
    # Lightweight background re-validation cadence. Clamped to >= 300s so the
    # gateway never hammers X with unnecessary traffic.
    SESSION_CHECK_INTERVAL_SECONDS: int = 1800
    SESSION_CHECK_TIMEOUT_SECONDS: int = 45
    VALIDATE_ON_STARTUP: bool = True

    # --- rate limits (aligned to upstream X user limits) -------------------
    # Gateway overall rate limit is raised to 1200/min so clients are bounded by
    # X's native endpoint limits rather than artificial gateway throttles.
    # Anti-burst identical-call pacing preserves documented defaults (2 concurrent, 1.5s gap).
    RATE_LIMIT_MCP_PER_MIN: int = 1200
    RATE_LIMIT_ADMIN_PER_MIN: int = 60
    MAX_REQUEST_BYTES: int = 1_000_000
    TOOL_MAX_CONCURRENT_IDENTICAL: int = 2
    TOOL_MIN_GAP_SECONDS: float = 1.5
    TOOL_GAP_JITTER_SECONDS: float = 3.0

    # --- admin UI / sessions ------------------------------------------------
    # Browser sessions for the admin dashboard: random HttpOnly cookies,
    # server-side store, this TTL. The ADMIN_TOKEN itself is never persisted
    # client-side.
    SESSION_TTL_HOURS: int = 8

    # --- usage logs / backups ------------------------------------------------
    USAGE_LOG_RETENTION_DAYS: int = 30
    BACKUP_INTERVAL_HOURS: int = 24
    # How long a backup snapshot is kept. Each run appends a new snapshot to
    # the backup store; snapshots older than this window are pruned after the
    # run (clamped to >= 1 day, so the snapshot just written always survives).
    BACKUP_RETENTION_DAYS: int = 10

    # --- runtime ------------------------------------------------------------
    LOG_LEVEL: str = "INFO"
    DEBUG: bool = False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def secret_strength_problems(settings: Settings) -> list[str]:
    """Return a list of human-readable problems with configured secrets.

    Empty values are not problems here (unset ⇒ feature disabled, which the
    auth layer reports as 503). Non-empty values below MIN_SECRET_LENGTH are
    refused: a short token is guessable and would silently expose /mcp or
    /admin to brute force.

    DEBUG deliberately does NOT relax this floor: a weak token saved in a
    dev .env is exactly the value that ends up deployed, and generating a
    strong one is a single command.
    """
    problems: list[str] = []
    for name, value in (("MCP_ACCESS_TOKEN", settings.MCP_ACCESS_TOKEN),
                        ("ADMIN_TOKEN", settings.ADMIN_TOKEN),
                        ("CREDENTIAL_ENCRYPTION_KEY", settings.CREDENTIAL_ENCRYPTION_KEY)):
        if value and len(value) < MIN_SECRET_LENGTH:
            problems.append(
                f"{name} is too weak: {len(value)} chars, minimum is "
                f"{MIN_SECRET_LENGTH}; {_GENERATE_HINT}"
            )
    return problems


def reset_settings_cache() -> None:
    get_settings.cache_clear()
