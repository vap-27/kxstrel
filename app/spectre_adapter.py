"""Adapter over the installed Spectre MCP server.

Design rules:
- Never rewrite the X client: reuse spectre's own FastMCP object, pool
  wiring and tool implementations verbatim.
- Never guess the tool list: enumerate it live from the installed package.
- Never touch a browser: spectre talks direct GraphQL/REST via twscrape.
- Session validation is one cheap authenticated call with a timeout.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import json
import os

from app import SPECTRE_PIN
from .logging_setup import get_logger, sanitize_error
from .models import XStatus

log = get_logger("kxstrel-x-mcp.spectre")

READ_ONLY_PREFIXES = ("get_", "search", "list_", "pool_status")

# State-changing tools that are hard to undo or visible to other people.
# Spectre already marks these with a warning sign in their descriptions;
# the gateway additionally surfaces them via GET /tools for client-side
# confirmation UX. They still require an explicit MCP tool call each time —
# nothing destructive ever runs as a side effect of a read.
DESTRUCTIVE_TOOLS = frozenset({
    "remove_account",
    "post_tweet", "upload_media", "delete_tweet",
    "clear_all_bookmarks",
    "unlike_tweet", "unretweet", "unbookmark_tweet",
    "follow_user", "unfollow_user",
    "mute_user", "unmute_user", "block_user", "unblock_user",
    "remove_follower",
    "send_dm", "dm_block_user", "dm_unblock_user",
    "create_list", "update_list", "delete_list",
    "add_list_member", "remove_list_member",
    "subscribe_list", "unsubscribe_list",
    "join_community", "leave_community",
    "follow_topic", "unfollow_topic",
    "rate_community_note",
    "update_profile", "update_profile_image", "update_profile_banner",
    "delete_profile_banner",
    "pin_tweet", "unpin_tweet", "pin_reply", "unpin_reply",
    "create_highlight", "delete_highlight",
    "create_bookmark_folder", "edit_bookmark_folder", "delete_bookmark_folder",
    "add_tweet_to_folder", "remove_tweet_from_folder",
    "schedule_tweet", "edit_scheduled_tweet", "delete_scheduled_tweet",
    "create_draft", "edit_draft", "delete_draft",
})


def is_read_only(tool_name: str) -> bool:
    return tool_name.startswith(READ_ONLY_PREFIXES)


def is_destructive(tool_name: str) -> bool:
    return tool_name in DESTRUCTIVE_TOOLS


def spectre_version() -> str:
    try:
        return importlib.metadata.version("spectre-mcp")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def check_spectre_pin() -> tuple[str, bool]:
    ver = spectre_version()
    return ver, (ver == SPECTRE_PIN)


class SpectreAdapter:
    """Bridges the gateway's encrypted store with spectre's local pool.

    Honest caveat: twscrape's pool file (SPECTRE_DB_PATH) is a *plaintext*
    local cache of the cookies it needs to operate — the encrypted store is
    the source of truth, but this cache exists at runtime. Mitigations: the
    file is chmod 0600, dropped accounts are VACUUMed out, and the path
    should point at ephemeral storage (it is rebuilt from the store on every
    boot). The remote-gateway threat model keeps MCP clients away from any
    file access (see tool_middleware.BLOCKED_TOOLS).
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        parent = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(parent, exist_ok=True)
        # Spectre resolves SPECTRE_DB lazily on each use, so setting it here
        # (before any tool call) is sufficient. No spectre code is modified.
        os.environ["SPECTRE_DB"] = db_path
        self._restrict_pool_file()
        self.operation_lock = asyncio.Lock()

    def _restrict_pool_file(self) -> None:
        """Best-effort 0600 on the plaintext pool cache."""
        try:
            if os.path.exists(self.db_path):
                os.chmod(self.db_path, 0o600)
        except Exception:
            pass  # Windows/permissions — non-fatal

    # -- pool sync ------------------------------------------------------
    async def sync_account(self, label: str, auth_token: str, ct0: str) -> None:
        async with self.operation_lock:
            return await self._sync_account(label, auth_token, ct0)

    async def _sync_account(self, label: str, auth_token: str, ct0: str) -> bool:
        """Insert/replace one account in spectre's local pool. Plaintext only
        ever lives in memory + the local pool cache; it is never logged."""
        from twscrape.accounts_pool import AccountsPool

        pool = AccountsPool(self.db_path)
        try:
            await pool.delete_accounts([label])
        except Exception:
            pass  # fresh pool or already absent — either is fine
        await pool.add_account_cookies(label, f"auth_token={auth_token}; ct0={ct0}")
        self._restrict_pool_file()
        log.info("spectre pool synced account label=%s", label)
        return True

    async def drop_account(self, label: str) -> bool:
        async with self.operation_lock:
            return await self._drop_account(label)

    async def _drop_account(self, label: str) -> bool:
        from twscrape.accounts_pool import AccountsPool

        pool = AccountsPool(self.db_path)
        try:
            await pool.delete_accounts([label])
        except Exception as exc:
            log.warning("spectre pool drop failed label=%s: %s", label, sanitize_error(str(exc)))
            return False
        # Deleted rows can linger in freelist pages of the plaintext cache;
        # VACUUM rewrites the file without them.
        try:
            import sqlite3

            def _vacuum() -> None:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("VACUUM")

            await asyncio.to_thread(_vacuum)
        except Exception as exc:
            log.debug("pool vacuum skipped: %s", sanitize_error(str(exc)))
        return True

    # -- validation ------------------------------------------------------
    async def validate(self, label: str, timeout: float) -> tuple[XStatus, str | None]:
        async with self.operation_lock:
            return await self._validate(label, timeout)

    async def _validate(self, label: str, timeout: float) -> tuple[XStatus, str | None]:
        """One cheap authenticated call (account settings). Returns
        (status, sanitized_detail). Never raises.

        Scopes the check to the labeled account where the writer supports
        it, and only inspects *structured* error fields — never the profile
        body (a bio containing "expired" must not flip the status)."""
        try:
            from spectre.server import _get_writer  # reuse spectre's own wiring

            writer = _get_writer()
            try:
                writer.set_preferred_account(label)
            except Exception:
                pass  # older spectre or empty pool — first-active fallback
            result = await asyncio.wait_for(writer.get_account_settings(), timeout)
            problem, rate_limited = _find_error_indicator(result)
            if problem:
                if rate_limited:
                    return XStatus.RATE_LIMITED, f"validation rejected: {problem}"
                return XStatus.INVALID_SESSION, f"validation rejected: {problem}"
            return XStatus.CONNECTED, None
        except asyncio.TimeoutError:
            return XStatus.X_UNAVAILABLE, "validation timed out"
        except Exception as exc:
            return _classify_exception(exc), sanitize_error(str(exc) or type(exc).__name__)

    async def pool_status(self) -> dict:
        try:
            from spectre.server import _get_scraper

            scraper = _get_scraper()
            result = await scraper.pool_status()
            if isinstance(result, str):
                return json.loads(result)
            if hasattr(result, "model_dump"):
                return result.model_dump()
            return {"pool": str(result)[:500]}
        except Exception as exc:
            return {"error": sanitize_error(str(exc))}

    # -- tool enumeration (dynamic; never hard-coded) --------------------
    async def list_tools(self) -> list[dict]:
        """Return the ACTUAL tools exposed by the installed spectre version.

        Version-proof: fastmcp<=3 exposes get_tools() (dict), fastmcp>=4
        exposes list_tools() (sequence). Either way the data comes from the
        live server object, never from a hard-coded list."""
        from spectre.server import mcp as spectre_mcp

        if hasattr(spectre_mcp, "get_tools"):
            tools = await spectre_mcp.get_tools()
            items = tools.items() if isinstance(tools, dict) else (
                (t.name, t) for t in tools)
        elif hasattr(spectre_mcp, "list_tools"):
            items = ((t.name, t) for t in await spectre_mcp.list_tools())
        else:  # pragma: no cover - defensive; pinned versions have one of these
            raise RuntimeError("installed FastMCP exposes no tool-listing API")
        out = []
        for name, tool in sorted(items, key=lambda kv: kv[0]):
            desc = getattr(tool, "description", "") or ""
            out.append({
                "name": name,
                "description": desc[:160],
                "read_only": is_read_only(name),
                "destructive": is_destructive(name),
            })
        return out


def _find_error_indicator(result: object) -> tuple[str | None, bool]:
    """Inspect only structured error fields, never the profile body.
    Returns (indicator, is_rate_limited)."""
    if isinstance(result, dict):
        errors = result.get("errors")
        if errors:
            text = json.dumps(errors, default=str)
            return sanitize_error(text, 120), "rate" in text.lower()
        if result.get("error"):
            return sanitize_error(str(result["error"]), 120), False
    elif isinstance(result, str) and result[:1] not in "{[":
        lowered = result.lower()
        if any(k in lowered for k in ("unauthorized", "forbidden", "expired",
                                      "invalid", "login required")):
            return "auth_error", False
        if "rate limit" in lowered or "429" in lowered:
            return "rate_limited", True
    return None, False


def _classify_exception(exc: Exception) -> XStatus:
    msg = f"{type(exc).__name__}: {exc}".lower()
    if any(k in msg for k in ("401", "unauthorized", "forbidden", "expired",
                              "bad token", "login required",
                              "could not authenticate")):
        return XStatus.INVALID_SESSION
    if any(k in msg for k in ("429", "rate limit", "too many requests")):
        return XStatus.RATE_LIMITED
    if any(k in msg for k in ("timeout", "timed out", "connect", "network",
                              "dns", "unreachable", "502", "503", "504")):
        return XStatus.X_UNAVAILABLE
    return XStatus.X_UNAVAILABLE
