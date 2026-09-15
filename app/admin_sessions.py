"""Server-side admin sessions for the dashboard UI.

Login exchanges the ADMIN_TOKEN for a random session id delivered as an
HttpOnly+Secure+SameSite=Strict cookie. The token itself is never stored
client-side and never re-sent by the browser. Sessions live server-side
(in-memory, plus Redis when REDIS_URL is set so multiple instances share
them) and expire after SESSION_TTL_HOURS.

Sessions are bound to the token that created them: the record carries a
short fingerprint of ADMIN_TOKEN and validate() re-checks it against the
current token, so rotating ADMIN_TOKEN invalidates every live session
(the cookie keeps its value but stops authorizing).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .logging_setup import get_logger

log = get_logger("kxstrel-x-mcp.sessions")


@dataclass
class _Session:
    expires: datetime
    token_fp: str


class AdminSessionStore:
    def __init__(self, admin_token: str, ttl_hours: int, redis_client=None):
        self.admin_token = admin_token
        self.ttl_hours = max(1, ttl_hours)
        self._redis = redis_client
        self._local: dict[str, _Session] = {}

    def _sid_key(self, sid: str) -> str:
        return f"kxstrel:admin_session:{sid}"

    def verify_token(self, token: str) -> bool:
        return bool(self.admin_token and token
                    and hmac.compare_digest(token.encode(), self.admin_token.encode()))

    def _hash_sid(self, sid: str) -> str:
        # Store only a hash server-side: a DB/Redis dump must not yield
        # usable cookies.
        return hashlib.sha256(sid.encode()).hexdigest()

    def _token_fingerprint(self) -> str:
        """Non-reversible fingerprint of the *current* ADMIN_TOKEN.

        Recomputed on every call (never cached) so a rotated token is
        detected immediately, including when the token attribute changes
        in-process."""
        if not self.admin_token:
            return ""
        return hashlib.sha256(self.admin_token.encode() + b"|kxstrel-admin-session").hexdigest()[:32]

    async def create(self) -> tuple[str, datetime]:
        sid = secrets.token_urlsafe(32)
        expires = datetime.now(timezone.utc) + timedelta(hours=self.ttl_hours)
        hashed = self._hash_sid(sid)
        record = _Session(expires=expires, token_fp=self._token_fingerprint())
        if self._redis is not None:
            try:
                await self._redis.set(self._sid_key(hashed), record.token_fp,
                                      ex=self.ttl_hours * 3600)
                return sid, expires
            except Exception:
                log.warning("redis session write failed; using local store")
        # Local fallback is also keyed by hash: a process memory dump must
        # not yield usable cookies either.
        self._local[hashed] = record
        return sid, expires

    async def validate(self, sid: str | None) -> bool:
        if not sid:
            return False
        hashed = self._hash_sid(sid)
        current_fp = self._token_fingerprint()
        if self._redis is not None:
            try:
                stored = await self._redis.get(self._sid_key(hashed))
                if stored is not None:
                    if isinstance(stored, bytes):
                        stored = stored.decode()
                    # Old records without a fingerprint never validate.
                    return bool(stored) and hmac.compare_digest(stored, current_fp)
            except Exception:
                pass
        record = self._local.get(hashed)
        if record is None:
            return False
        if datetime.now(timezone.utc) >= record.expires:
            self._local.pop(hashed, None)
            return False
        return bool(record.token_fp) and hmac.compare_digest(record.token_fp, current_fp)

    async def revoke(self, sid: str | None) -> None:
        if not sid:
            return
        hashed = self._hash_sid(sid)
        if self._redis is not None:
            try:
                await self._redis.delete(self._sid_key(hashed))
            except Exception:
                pass
        self._local.pop(hashed, None)

    def prune_local(self) -> None:
        now = datetime.now(timezone.utc)
        for key in [k for k, rec in self._local.items() if now >= rec.expires]:
            self._local.pop(key, None)

    # ── inventory / mass revocation (admin dashboard) ──────────────────
    _SCAN_PATTERN = "kxstrel:admin_session:*"

    async def list_sessions(self) -> list[dict]:
        """Active admin sessions (server-side view; cookie values never
        leave — only creation time and hash prefixes)."""
        out: list[dict] = []
        if self._redis is not None:
            try:
                created = {}
                async for key in self._redis.scan_iter(match=self._SCAN_PATTERN, count=100):
                    ttl = await self._redis.ttl(key)
                    remaining = max(0, ttl)
                    age = self.ttl_hours * 3600 - remaining
                    out.append({
                        "source": "redis",
                        "hash_prefix": key.decode()[-8:] if isinstance(key, bytes) else str(key)[-8:],
                        "age_seconds": int(age),
                        "expires_in_seconds": int(remaining),
                    })
                return out
            except Exception:
                pass
        now = datetime.now(timezone.utc)
        for hashed, record in self._local.items():
            out.append({
                "source": "local",
                "hash_prefix": hashed[:8],
                "age_seconds": int((self.ttl_hours * 3600) - (record.expires - now).total_seconds()),
                "expires_in_seconds": int((record.expires - now).total_seconds()),
            })
        return out

    async def revoke_all(self) -> int:
        count = 0
        if self._redis is not None:
            try:
                keys = [key async for key in
                        self._redis.scan_iter(match=self._SCAN_PATTERN, count=100)]
                if keys:
                    count += await self._redis.delete(*keys)
            except Exception:
                pass
        count += len(self._local)
        self._local.clear()
        return count


async def build_session_store(settings) -> AdminSessionStore:
    redis_client = None
    if settings.REDIS_URL:
        try:
            import redis.asyncio as aioredis

            redis_client = aioredis.from_url(
                settings.REDIS_URL, socket_timeout=5, socket_connect_timeout=5
            )
            await redis_client.ping()
            log.info("redis connected for shared admin sessions")
        except Exception as exc:
            from .logging_setup import sanitize_error

            log.warning("redis unavailable (%s); using in-memory sessions",
                        sanitize_error(str(exc)))
            redis_client = None
    return AdminSessionStore(settings.ADMIN_TOKEN, settings.SESSION_TTL_HOURS, redis_client)
