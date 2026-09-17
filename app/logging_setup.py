"""Structured logging with secret redaction.

Never logs: auth_token, ct0, cookies, Authorization headers, DB passwords,
encryption keys, MCP/admin tokens. Both an explicit blocklist of env-derived
values and pattern-based scrubbing are applied to every record.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone

# Long opaque blobs (>=40 chars of token alphabet) are almost certainly
# secrets (ct0 is 160 hex chars, auth_token is a long hex string, Fernet
# keys/tokens are similar). Scrub them wherever they appear.
_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/=]{40,}")
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[^\s\"']+")
# key=value and key: value with optional JSON/single quotes around the
# value ({"auth_token": "abc"} / auth_token='abc' both scrub).
_COOKIE_ASSIGN_RE = re.compile(
    r"(?i)(auth_token|ct0|cookie|session|password|secret|token|key)"
    r"\s*[\"']?\s*[:=]\s*[\"']?[^\s,;\"'}]+"
)
_URL_PASSWORD_RE = re.compile(r"(?i)(://[^:/\s]+:)[^@\s]+(@)")

# Explicit secret values picked up from the environment at setup time.
_KNOWN_SECRETS: list[str] = []


def register_secret(value: str | None) -> None:
    if value and len(value) >= 4 and value not in _KNOWN_SECRETS:
        _KNOWN_SECRETS.append(value)


def register_secrets_from_env() -> None:
    for name in (
        "MCP_ACCESS_TOKEN",
        "ADMIN_TOKEN",
        "CREDENTIAL_ENCRYPTION_KEY",
        "DATABASE_URL",
        "BACKUP_DATABASE_URL",
        "REDIS_URL",
        "TWITTER_AUTH_TOKEN",
        "TWITTER_CT0",
    ):
        register_secret(os.environ.get(name))


def redact(text: str) -> str:
    if not text:
        return text
    out = text
    for secret in _KNOWN_SECRETS:
        if secret in out:
            out = out.replace(secret, "[redacted]")
    out = _BEARER_RE.sub(r"\1[redacted]", out)
    out = _URL_PASSWORD_RE.sub(r"\1[redacted]\2", out)
    out = _COOKIE_ASSIGN_RE.sub(r"\1=[redacted]", out)
    # Last pass: any remaining long opaque blob.
    out = _LONG_TOKEN_RE.sub("[redacted]", out)
    return out


def sanitize_error(message: str, limit: int = 300) -> str:
    """Turn an upstream exception into a short, secret-free status string."""
    return redact(message)[:limit]


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 - stdlib name
        try:
            if record.args:
                redacted = []
                for arg in record.args:  # type: ignore[attr-defined]
                    if isinstance(arg, str):
                        redacted.append(redact(arg))
                    else:
                        redacted.append(arg)
                record.args = tuple(redacted)  # type: ignore[assignment]
            if isinstance(record.msg, str):
                record.msg = redact(record.msg)
        except Exception:
            record.msg = "[log-redaction-fallback]"
            record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        try:
            message = record.getMessage()
        except Exception:
            # Fallback if %-formatting fails (e.g. mismatched args); never crash logging
            message = str(record.msg)
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(message),
        }
        request_id = getattr(record, "request_id", None)
        if request_id:
            payload["request_id"] = request_id
        if record.exc_info and record.exc_type is not None:
            payload["exc"] = redact(self.formatException(record.exc_info))[:2000]
        return json.dumps(payload)


_configured = False


def setup_logging(level: str = "INFO") -> logging.Logger:
    global _configured
    import warnings
    # Suppress benign MySQL "Table already exists" warnings emitted during CREATE TABLE IF NOT EXISTS
    warnings.filterwarnings("ignore", message=r".*already exists.*", category=Warning)

    register_secrets_from_env()
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # Quiet noisy third-party loggers; keep warnings+.
    for noisy in ("twscrape", "httpx", "httpcore", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _configured = True
    return logging.getLogger("kxstrel-x-mcp")


def get_logger(name: str = "kxstrel-x-mcp") -> logging.Logger:
    if not _configured:
        return setup_logging(os.environ.get("LOG_LEVEL", "INFO"))
    return logging.getLogger(name)
