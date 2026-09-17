"""Admin dashboard: session-based UI + JSON API + legacy bearer endpoints.

Auth model:
- Browser: POST /admin/api/login exchanges ADMIN_TOKEN for an HttpOnly
  session cookie (server-side store). Token never persisted client-side.
- Scripts: Authorization: Bearer ADMIN_TOKEN works on every /admin/api/* and
  legacy path (AuthMiddleware accepts either).
- CSRF: cookie-authenticated state-changing requests must send the
  X-Requested-With header (the UI always does).

Nothing under /admin ever returns credentials, ciphertext, cookies or tokens.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse

from . import upstream_capture
from .logging_setup import get_logger, sanitize_error
from .middleware import client_key as _client_key
from .models import XStatus
from .security import extract_bearer

log = get_logger("kxstrel-x-mcp.admin")
router = APIRouter(prefix="/admin")

_LABEL_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
STATIC_DIR = Path(__file__).parent / "static"
COOKIE_NAME = "kxstrel_admin_session"


# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────

def _rid(request: Request) -> str:
    return getattr(request.state, "request_id", "-")


def _session_id(request: Request) -> str | None:
    return request.cookies.get(COOKIE_NAME)


async def _authenticated(request: Request) -> bool:
    sessions = getattr(request.app.state, "admin_sessions", None)
    if sessions is None:
        return False
    if await sessions.validate(_session_id(request)):
        return True
    return sessions.verify_token(extract_bearer(request))


def _auth_method(request: Request) -> str:
    """How the caller authenticated: 'bearer' (ADMIN_TOKEN), 'session'
    (dashboard session cookie) or 'none'.

    The method label deliberately avoids the word "cookie" so the existing
    secret-leak tripwire on admin responses ("the string cookie must never
    appear") stays meaningful — no cookie name or value is recorded."""
    sessions = getattr(request.app.state, "admin_sessions", None)
    if sessions is not None and sessions.verify_token(extract_bearer(request)):
        return "bearer"
    if _session_id(request):
        return "session"
    return "none"


async def require_admin_access(request: Request) -> None:
    """Explicit authenticated-admin gate for every protected /admin route.

    AuthMiddleware already gates /admin/*, but relying on a single prefix
    check means one future mount/path-matching mistake silently exposes
    data. Each protected route therefore declares this dependency too.
    Accepts an admin session cookie (browser) or ADMIN_TOKEN bearer (scripts);
    never the MCP token.
    """
    if not await _authenticated(request):
        log.info("admin route denied caller=%s rid=%s", _client_key(request), _rid(request))
        raise HTTPException(
            status_code=401,
            detail="invalid or missing admin access token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )


async def anti_csrf(request: Request) -> None:
    """Cookie-authenticated state changes must carry X-Requested-With.

    Bearer-authenticated requests (scripts) are exempt: the Authorization
    header is deliberate, non-ambient authority that cross-site pages
    cannot attach."""
    sessions = getattr(request.app.state, "admin_sessions", None)
    if sessions is None:
        # Fail open (the route's auth dependency still applies), but never
        # silently: a missing session store means CSRF protection is off.
        log.warning("anti_csrf: admin_sessions unavailable; CSRF check skipped rid=%s",
                    _rid(request))
        return
    if sessions.verify_token(extract_bearer(request)):
        return
    if await sessions.validate(_session_id(request)):
        header = (request.headers.get("x-requested-with") or "").strip().lower()
        if header != "xmlhttprequest":
            raise HTTPException(status_code=403, detail="Missing X-Requested-With header")


def _json(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)


async def _audit(request: Request, action: str, detail: str | None = None) -> None:
    from . import metrics_setup

    metrics_setup.admin_actions_total.labels(action=action[:64]).inc()
    store = request.app.state.store
    if store is None:
        return
    # Caller attribution: source key (trusted-proxy-aware IP) + auth method.
    # The token itself (or any part of it) is never recorded.
    caller = _client_key(request)
    detail_with_caller = f"{detail or ''}; caller={caller} via={_auth_method(request)}"
    try:
        await store.log_admin_action(action, detail_with_caller, _rid(request))
    except Exception as exc:
        log.warning("audit write failed: %s", sanitize_error(str(exc)))


# ─────────────────────────────────────────────────────────────────────────
# Public: UI shell, assets, login/session
# ─────────────────────────────────────────────────────────────────────────

@router.get("")
@router.get("/")
async def admin_ui():
    return FileResponse(STATIC_DIR / "admin.html", media_type="text/html")


class LoginBody(BaseModel):
    token: str


@router.post("/api/login")
async def login(body: LoginBody, request: Request):
    sessions = request.app.state.admin_sessions
    if sessions is None or not sessions.verify_token(body.token):
        await _audit(request, "login_failed")
        return _json(401, "unauthorized", "Invalid admin token")
    sid, expires = await sessions.create()
    await _audit(request, "login_ok")
    resp = JSONResponse({"ok": True, "expires_at": expires.isoformat()})
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    resp.set_cookie(
        COOKIE_NAME, sid,
        max_age=sessions.ttl_hours * 3600,
        httponly=True, secure=secure, samesite="strict", path="/admin",
    )
    return resp


@router.post("/api/logout")
async def logout(request: Request):
    await anti_csrf(request)
    sessions = request.app.state.admin_sessions
    if sessions is not None:
        await sessions.revoke(_session_id(request))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE_NAME, path="/admin")
    return resp


@router.get("/api/session")
async def session_info(request: Request):
    return {"authenticated": await _authenticated(request)}


# ─────────────────────────────────────────────────────────────────────────
# API: overview / accounts / tools / usage / audit / backup
# ─────────────────────────────────────────────────────────────────────────

@router.get("/api/overview", dependencies=[Depends(require_admin_access)])
async def overview(request: Request):
    state = request.app.state.state
    settings = request.app.state.settings
    store = request.app.state.store
    usage = {}
    if store is not None:
        try:
            if not state.db_ok:
                state.db_ok = await store.ping()
            if state.db_ok:
                metas = await store.list_accounts_meta()
                state.accounts_configured = len(metas)
                state.accounts_enabled = sum(1 for m in metas if m.get("enabled"))
                if metas:
                    from .session_monitor import aggregate_status
                    enabled_statuses = [
                        XStatus(m["status"])
                        for m in metas
                        if m.get("enabled") and m.get("status")
                    ]
                    if enabled_statuses:
                        state.x_status = aggregate_status(enabled_statuses)
                    else:
                        state.x_status = XStatus.NOT_CONFIGURED
                elif not state.restored_from_snapshot:
                    state.x_status = XStatus.NOT_CONFIGURED
        except Exception as exc:
            log.warning("overview account sync failed: %s", sanitize_error(str(exc)))
        try:
            usage = await store.usage_summary(days=7)
        except Exception:
            usage = {}
    registry = getattr(request.app.state, "client_registry", None)
    clients = registry.snapshot() if registry is not None else []
    backup_manager = getattr(request.app.state, "backup_manager", None)
    snapshots: list[dict] = []
    if backup_manager is not None:
        try:
            # Index rows only (timestamps + row counts) — never credentials.
            snapshots = await backup_manager.list_snapshots(limit=20)
        except Exception as exc:
            log.warning("snapshot listing failed: %s", sanitize_error(str(exc)))
    return {
        "x_status": state.x_status.value,
        "db_ok": state.db_ok,
        "db_backend": state.db_backend,
        "mcp_ok": state.mcp_ok,
        "tool_count": state.tool_count,
        "spectre_version": state.spectre_version,
        "spectre_pin": state.spectre_pin,
        "spectre_version_ok": state.spectre_version_ok,
        "accounts_configured": state.accounts_configured,
        "accounts_enabled": state.accounts_enabled,
        "last_checked_at": state.last_checked_at,
        "last_error": state.last_error,
        "started_at": state.started_at,
        "server_now": datetime.now(timezone.utc).isoformat(),
        "service_first_started_at": state.service_first_started_at,
        "mcp_first_ok_at": state.mcp_first_ok_at,
        "mcp_clients": clients,
        "mcp_client_count": len(clients),
        "backup": {
            "ok": state.backup_ok,
            "backend": state.backup_backend,
            "last_backup_at": state.last_backup_at,
            "last_backup_error": state.last_backup_error,
            "interval_hours": settings.BACKUP_INTERVAL_HOURS,
            "retention_days": settings.BACKUP_RETENTION_DAYS,
            "last_snapshot_at": state.last_backup_snapshot_at,
            "restored_from_snapshot": state.restored_from_snapshot,
            "snapshots": snapshots,
        },
        "usage_7d": usage,
    }


class AccountSetup(BaseModel):
    label: str = Field(description="Account identifier, e.g. myaccount")
    auth_token: str = Field(description="X web-session auth_token cookie value")
    ct0: str = Field(description="X web-session ct0 cookie value")
    enabled: bool = True
    meta: dict = Field(default_factory=dict)


def _validate_cookies(auth_token: str, ct0: str) -> list[str]:
    warnings: list[str] = []
    if len(auth_token.strip()) < 20:
        warnings.append("auth_token looks too short — double-check the full cookie value")
    if len(ct0.strip()) < 40:
        warnings.append("ct0 looks too short — double-check the full cookie value")
    if len(ct0.strip()) != 160:
        warnings.append("ct0 is usually exactly 160 characters; a partial value fails silently")
    return warnings


async def _setup_account_impl(request: Request, body: AccountSetup) -> JSONResponse | dict:
    store = request.app.state.store
    crypto = request.app.state.crypto
    adapter = request.app.state.adapter
    state = request.app.state.state
    settings = request.app.state.settings

    if not body.label or not _LABEL_RE.match(body.label):
        return _json(400, "invalid_account", "label must match [A-Za-z0-9_]{1,64}")
    if crypto is None:
        return _json(503, "config_error", "Credential encryption is not configured")
    warnings = _validate_cookies(body.auth_token, body.ct0)
    try:
        enc_auth = crypto.encrypt(body.auth_token.strip())
        enc_ct0 = crypto.encrypt(body.ct0.strip())
        try:
            await store.upsert_account(body.label, enc_auth, enc_ct0,
                                       enabled=body.enabled, meta=json.dumps(body.meta or {}))
        except Exception:
            # If the store was degraded or disconnected at startup, try one reconnect
            await store.connect()
            await store.init_schema()
            await store.upsert_account(body.label, enc_auth, enc_ct0,
                                       enabled=body.enabled, meta=json.dumps(body.meta or {}))
    except Exception as exc:
        log.warning("account setup db failure rid=%s: %s", _rid(request), sanitize_error(str(exc)))
        return _json(503, "database_error", f"Could not persist the account: {sanitize_error(str(exc))}")
    x_status, detail = XStatus.NOT_CONFIGURED, None
    if body.enabled:
        try:
            await adapter.sync_account(body.label, body.auth_token.strip(), body.ct0.strip())
            x_status, detail = await adapter.validate(body.label, settings.SESSION_CHECK_TIMEOUT_SECONDS)
        except Exception as exc:
            x_status, detail = XStatus.X_UNAVAILABLE, sanitize_error(str(exc))
        try:
            await store.update_status(body.label, x_status.value, x_status == XStatus.CONNECTED, detail)
        except Exception:
            pass
    else:
        try:
            await store.update_status(body.label, XStatus.NOT_CONFIGURED.value, None, "disabled by admin")
        except Exception:
            pass
    try:
        metas = await store.list_accounts_meta()
        from .session_monitor import aggregate_status
        state.x_status = aggregate_status([XStatus(m["status"]) for m in metas if m["enabled"]])
        state.accounts_configured = len(metas)
        state.accounts_enabled = sum(1 for m in metas if m["enabled"])
        state.last_checked_at = datetime.now(timezone.utc).isoformat()
    except Exception:
        pass
    await _audit(request, "account_setup", f"label={body.label} enabled={body.enabled} -> {x_status.value}")
    log.info("account setup label=%s enabled=%s x_status=%s rid=%s",
             body.label, body.enabled, x_status.value, _rid(request))
    return {"label": body.label, "enabled": body.enabled,
            "x_status": x_status.value, "warnings": warnings}


@router.post("/api/accounts", dependencies=[Depends(require_admin_access)])
async def setup_account(body: AccountSetup, request: Request):
    await anti_csrf(request)
    result = await _setup_account_impl(request, body)
    return result


# Legacy bearer-compatible path (scripts/setup_account.py uses this).
@router.post("/account", dependencies=[Depends(require_admin_access)])
async def setup_account_legacy(body: AccountSetup, request: Request):
    await anti_csrf(request)
    return await _setup_account_impl(request, body)


@router.get("/api/accounts", dependencies=[Depends(require_admin_access)])
async def list_accounts(request: Request):
    try:
        return {"accounts": await request.app.state.store.list_accounts_meta()}
    except Exception as exc:
        log.warning("admin list failed: %s", sanitize_error(str(exc)))
        return {"accounts": [], "warning": "Database is reconnecting or unavailable"}


# Legacy path kept for scripts.
@router.get("/accounts", dependencies=[Depends(require_admin_access)])
async def list_accounts_legacy(request: Request):
    return await list_accounts(request)


class EnabledBody(BaseModel):
    enabled: bool


@router.patch("/api/accounts/{label}", dependencies=[Depends(require_admin_access)])
async def toggle_account(label: str, body: EnabledBody, request: Request):
    await anti_csrf(request)
    store = request.app.state.store
    adapter = request.app.state.adapter
    state = request.app.state.state
    try:
        if not body.enabled:
            async with adapter.operation_lock:
                if not await store.set_account_enabled(label, False):
                    return _json(404, "not_found", f"No account '{label}'")
                await store.update_status(label, XStatus.NOT_CONFIGURED.value, None, "disabled by admin")
                removed = await adapter._drop_account(label)
                if not removed:
                    await store.set_account_enabled(label, True)
                    return _json(503, "pool_error", "Could not remove the account from the active pool")
        else:
            record = next((a for a in await store.get_all_accounts() if a.label == label), None)
            if record is None:
                return _json(404, "not_found", f"No account '{label}'")
            if request.app.state.crypto is None:
                return _json(503, "config_error", "Credential encryption is not configured")
            try:
                async with adapter.operation_lock:
                    auth_token = request.app.state.crypto.decrypt(record.enc_auth_token)
                    ct0 = request.app.state.crypto.decrypt(record.enc_ct0)
                    await adapter._sync_account(label, auth_token, ct0)
                    await store.set_account_enabled(label, True)
                    status, detail = await adapter._validate(
                        label, request.app.state.settings.SESSION_CHECK_TIMEOUT_SECONDS
                    )
                    await store.update_status(label, status.value, status == XStatus.CONNECTED, detail)
            except Exception as exc:
                await store.set_account_enabled(label, False)
                await store.update_status(label, XStatus.X_UNAVAILABLE.value, False,
                                          sanitize_error(str(exc)))
                return _json(503, "pool_error", "Could not restore and validate the account")
        metas = await store.list_accounts_meta()
        from .session_monitor import aggregate_status
        state.x_status = aggregate_status([XStatus(m["status"]) for m in metas if m["enabled"]])
        state.accounts_configured = len(metas)
        state.accounts_enabled = sum(1 for m in metas if m["enabled"])
    except Exception as exc:
        log.warning("toggle account failed: %s", sanitize_error(str(exc)))
        return _json(503, "database_error", "Could not update the account")
    await _audit(request, "account_toggle", f"label={label} enabled={body.enabled}")
    return {"label": label, "enabled": body.enabled}


@router.delete("/api/accounts/{label}", dependencies=[Depends(require_admin_access)])
async def delete_account(label: str, request: Request):
    await anti_csrf(request)
    store = request.app.state.store
    adapter = request.app.state.adapter
    state = request.app.state.state
    try:
        async with adapter.operation_lock:
            removed_from_pool = await adapter._drop_account(label)
            if not removed_from_pool:
                return _json(503, "pool_error", "Could not remove the account from the active pool")
            removed = await store.delete_account(label)
    except Exception as exc:
        log.warning("account delete failed label=%s: %s", label, sanitize_error(str(exc)))
        return _json(503, "database_error", "Could not delete the account")
    if not removed:
        return _json(404, "not_found", f"No account '{label}'")
    try:
        metas = await store.list_accounts_meta()
        from .session_monitor import aggregate_status
        state.x_status = aggregate_status([XStatus(m["status"]) for m in metas if m["enabled"]])
        state.accounts_configured = len(metas)
        state.accounts_enabled = sum(1 for m in metas if m["enabled"])
    except Exception:
        pass
    await _audit(request, "account_delete", f"label={label}")
    log.info("account deleted label=%s", label)
    return {"deleted": label}


# Legacy path (scripts).
@router.delete("/account/{label}", dependencies=[Depends(require_admin_access)])
async def delete_account_legacy(label: str, request: Request):
    return await delete_account(label, request)


@router.post("/api/validate", dependencies=[Depends(require_admin_access)])
async def validate_now(request: Request, label: str | None = None):
    await anti_csrf(request)
    monitor = request.app.state.monitor
    results = await monitor.check_once(source="admin")
    await _audit(request, "validate", f"label={label or 'all'}")
    if label:
        status = results.get(label)
        if status is None:
            return _json(404, "not_found", f"No enabled account '{label}'")
        return {"label": label, "x_status": status}
    return {"results": results, "x_status": request.app.state.state.x_status.value}


# Legacy path.
@router.post("/validate", dependencies=[Depends(require_admin_access)])
async def validate_now_legacy(request: Request, label: str | None = None):
    return await validate_now(request, label)


@router.get("/api/tools", dependencies=[Depends(require_admin_access)])
async def tools_listing(request: Request):
    adapter = request.app.state.adapter
    store = request.app.state.store
    if adapter is None:
        return _json(503, "not_ready", "Gateway is still starting")
    try:
        tool_list = await adapter.list_tools()
        flags = await store.list_tool_flags() if store is not None else {}
    except Exception as exc:
        log.warning("admin tools listing failed: %s", sanitize_error(str(exc)))
        return _json(502, "spectre_error", "Could not enumerate tools")
    for tool in tool_list:
        tool["enabled"] = flags.get(tool["name"], True)
    return {"count": len(tool_list), "tools": tool_list}


@router.post("/api/tools/{name}", dependencies=[Depends(require_admin_access)])
async def toggle_tool(name: str, body: EnabledBody, request: Request):
    await anti_csrf(request)
    store = request.app.state.store
    if store is None:
        return _json(503, "database_error", "Store unavailable")
    try:
        await store.set_tool_flag(name, body.enabled)
        mw = getattr(request.app.state, "tool_middleware", None)
        if mw is not None:
            await mw.refresh_flags()
    except Exception as exc:
        log.warning("tool toggle failed: %s", sanitize_error(str(exc)))
        return _json(503, "database_error", "Could not update the tool flag")
    await _audit(request, "tool_toggle", f"tool={name} enabled={body.enabled}")
    return {"tool": name, "enabled": body.enabled}


@router.get("/api/usage", dependencies=[Depends(require_admin_access)])
async def usage(request: Request, limit: int = 50, offset: int = 0,
                tool: str | None = None, ok: bool | None = None):
    store = request.app.state.store
    if store is None:
        return _json(503, "database_error", "Store unavailable")
    try:
        limit = max(1, min(limit, 200))
        offset = max(0, offset)
        rows = await store.list_tool_usage(limit=limit, offset=offset, tool=tool, ok=ok)
        total = await store.count_tool_usage(tool=tool, ok=ok)
        return {"rows": rows, "total": total, "limit": limit, "offset": offset}
    except Exception as exc:
        log.warning("usage listing failed: %s", sanitize_error(str(exc)))
        return _json(503, "database_error", "Could not read usage logs")


@router.get("/api/audit", dependencies=[Depends(require_admin_access)])
async def audit(request: Request, limit: int = 50, offset: int = 0):
    store = request.app.state.store
    if store is None:
        return _json(503, "database_error", "Store unavailable")
    try:
        limit = max(1, min(limit, 200))
        rows = await store.list_admin_audit(limit=limit, offset=max(0, offset))
        return {"rows": rows, "limit": limit, "offset": offset}
    except Exception as exc:
        log.warning("audit listing failed: %s", sanitize_error(str(exc)))
        return _json(503, "database_error", "Could not read the audit log")


@router.post("/api/backup", dependencies=[Depends(require_admin_access)])
async def trigger_backup(request: Request):
    await anti_csrf(request)
    backup = request.app.state.backup_manager
    if backup is None:
        return _json(503, "config_error", "Backup is not configured")
    result = await backup.run(triggered_by="admin")
    await _audit(request, "backup_trigger", f"ok={result.get('ok')}")
    return result


class RestoreSnapshotBody(BaseModel):
    snapshot_at: str | None = Field(
        default=None, description="Snapshot timestamp to restore; the newest one when omitted")


@router.post("/api/backup/restore", dependencies=[Depends(require_admin_access)])
async def restore_backup(request: Request, body: RestoreSnapshotBody | None = None):
    """Write a snapshot back into the PRIMARY store (explicit operator action).

    This is the only path that writes a snapshot into the primary store:
    automatic fallback only ever hydrates the local Spectre pool, so
    resurrecting a deleted account — or repairing a corrupt credential row —
    is always deliberate. Restoring upserts and resurrects; accounts that
    exist only on the primary are left alone.
    """
    await anti_csrf(request)
    backup = request.app.state.backup_manager
    if backup is None:
        return _json(503, "config_error", "Backup is not configured")
    snapshot_at = (body.snapshot_at if body else None) or None
    try:
        target = snapshot_at or await backup.latest_snapshot()
        if target is None:
            await _audit(request, "backup_restore", "ok=False error=no snapshots")
            return _json(404, "no_snapshots", "The backup store holds no snapshot to restore")
        if snapshot_at is not None and not await backup.snapshot_exists(snapshot_at):
            await _audit(request, "backup_restore", f"snapshot_at={snapshot_at} ok=False not_found")
            return _json(404, "snapshot_not_found", "No snapshot with that timestamp")
        result = await backup.restore_snapshot(target)
    except Exception as exc:
        log.warning("backup restore failed rid=%s: %s", _rid(request), sanitize_error(str(exc)))
        return _json(503, "restore_failed", "Could not read the snapshot")
    await _audit(request, "backup_restore",
                 f"snapshot_at={result.get('snapshot_at')} ok={result.get('ok')} "
                 f"accounts={result.get('accounts')} flags={result.get('tool_flags')} "
                 f"audit={result.get('admin_audit')}")
    if not result.get("ok"):
        return _json(503, "restore_failed", str(result.get("error") or "restore failed"))
    # Rebuild the pool from the primary so the restored accounts take effect
    # now instead of at the next scheduled check. validate=False: no X
    # traffic in an admin request; the monitor validates on its own cadence.
    hydrated = False
    monitor = getattr(request.app.state, "monitor", None)
    if monitor is not None:
        try:
            await monitor.check_once(source="restore", validate=False)
            hydrated = True
        except Exception as exc:
            log.warning("restore: pool re-hydration failed rid=%s: %s",
                        _rid(request), sanitize_error(str(exc)))
    return {**result, "pool_hydrated": hydrated}


@router.delete("/api/backup/snapshots/{snapshot_at:path}", dependencies=[Depends(require_admin_access)])
async def delete_backup_snapshot(snapshot_at: str, request: Request):
    await anti_csrf(request)
    backup = request.app.state.backup_manager
    if backup is None:
        return _json(503, "config_error", "Backup is not configured")
    try:
        if not await backup.snapshot_exists(snapshot_at):
            return _json(404, "snapshot_not_found", "No snapshot with that timestamp")
        deleted = await backup.delete_snapshot(snapshot_at)
        if not deleted:
            return _json(404, "snapshot_not_found", "Could not find or delete snapshot")
    except Exception as exc:
        log.warning("backup delete failed snapshot_at=%s: %s", snapshot_at, sanitize_error(str(exc)))
        return _json(503, "delete_failed", "Could not delete the snapshot")
    await _audit(request, "backup_delete", f"snapshot_at={snapshot_at} ok=True")
    log.info("backup snapshot deleted snapshot_at=%s rid=%s", snapshot_at, _rid(request))
    return {"deleted": snapshot_at}


# ─────────────────────────────────────────────────────────────────────────
# API: live MCP clients, tool tester, admin sessions
# ─────────────────────────────────────────────────────────────────────────

@router.get("/api/clients", dependencies=[Depends(require_admin_access)])
async def mcp_clients(request: Request):
    """Real client identification from actual MCP initialize handshakes."""
    registry = getattr(request.app.state, "client_registry", None)
    if registry is None:
        return {"clients": [], "note": "registry unavailable"}
    return {"clients": registry.snapshot()}


class ToolTestBody(BaseModel):
    arguments: dict = Field(default_factory=dict)
    allow_non_read_only: bool = Field(
        default=False,
        description=("Explicit opt-in required to run state-changing (write) tools "
                     "from the tester. Read-only tools need no flag."),
    )


@router.post("/api/tools/{name}/test", dependencies=[Depends(require_admin_access)])
async def test_tool(name: str, body: ToolTestBody, request: Request):
    """Run one read-only tool in-process from the dashboard.

    The FastMCP middleware chain is traversed by ``call_tool`` (verified by
    test_fastmcp_call_tool_runs_middleware), but the tester does not rely on
    that: hard blocks, local-file arguments, per-tool flags and the
    read-only default are all enforced here as well, so the invariant
    survives a fastmcp version change.

    Set ``allow_non_read_only: true`` to run a state-changing tool on
    purpose; destructive tools stay reachable only this way, never by
    accident.
    """
    await anti_csrf(request)
    from .spectre_adapter import is_read_only
    from .tool_middleware import BLOCKED_TOOLS, contains_file_path

    if not request.app.state.state.policy_ready:
        return _json(503, "policy_unavailable", "MCP policy is temporarily unavailable")
    if name in BLOCKED_TOOLS:
        return _json(403, "blocked", "This tool is hard-blocked in remote gateway mode")
    if contains_file_path(body.arguments):
        return _json(403, "blocked",
                     "Arguments carrying a server-local file_path are refused")
    store = request.app.state.store
    if store is None:
        return _json(503, "policy_unavailable", "MCP policy is temporarily unavailable")
    try:
        if not await store.get_tool_flag(name):
            return _json(403, "disabled", f"Tool '{name}' is disabled by the administrator")
    except Exception as exc:
        log.warning("tool flag read failed in tester: %s", sanitize_error(str(exc)))
        return _json(503, "policy_unavailable", "MCP policy is temporarily unavailable")
    if not is_read_only(name) and not body.allow_non_read_only:
        return _json(
            403, "write_tool_requires_opt_in",
            f"'{name}' is not a read-only tool; resend with allow_non_read_only=true "
            "to run it deliberately",
        )
    try:
        from spectre.server import mcp as spectre_mcp

        result = await spectre_mcp.call_tool(name, body.arguments)
    except Exception as exc:
        await _audit(request, "tool_test", f"tool={name} error")
        return {"ok": False, "error": sanitize_error(f"{type(exc).__name__}: {exc}")[:400]}
    await _audit(request, "tool_test",
                 f"tool={name} read_only={is_read_only(name)} "
                 f"opt_in={body.allow_non_read_only}")
    # Render whatever the tool returned as displayable text.
    try:
        if hasattr(result, "content"):
            texts = [getattr(c, "text", str(c)) for c in result.content]
            payload = texts[0] if len(texts) == 1 else "\n---\n".join(texts)
        else:
            payload = json.dumps(result, indent=2, default=str)
    except Exception:
        payload = str(result)
    is_error = bool(getattr(result, "is_error", False))
    return {"ok": not is_error, ("error" if is_error else "result"): payload[:20000]}


@router.get("/api/sessions", dependencies=[Depends(require_admin_access)])
async def admin_sessions(request: Request):
    sessions = request.app.state.admin_sessions
    if sessions is None:
        return _json(503, "config_error", "Sessions are not configured")
    return {"sessions": await sessions.list_sessions()}


@router.delete("/api/sessions", dependencies=[Depends(require_admin_access)])
async def revoke_admin_sessions(request: Request):
    await anti_csrf(request)
    sessions = request.app.state.admin_sessions
    if sessions is None:
        return _json(503, "config_error", "Sessions are not configured")
    count = await sessions.revoke_all()
    await _audit(request, "sessions_revoke_all", f"count={count}")
    return {"revoked": count}


# ─────────────────────────────────────────────────────────────────────────
# API: upstream capture (diagnostic, off by default)
# ─────────────────────────────────────────────────────────────────────────

class UpstreamCaptureBody(BaseModel):
    operations: list[str] | None = Field(
        default=None,
        description="Restrict capture to these GraphQL operation names; empty/null captures all.",
    )


@router.post("/api/upstream-capture", dependencies=[Depends(require_admin_access)])
async def enable_upstream_capture(request: Request, body: UpstreamCaptureBody | None = None):
    """Enable in-memory capture of upstream GraphQL write responses.

    Installs the pass-through hook on first enable (never at import) and
    clears the buffer. Returns the current state; no upstream payload is
    stored here — only operation names, parsed variables and parsed responses
    after redaction.
    """
    await anti_csrf(request)
    operations = body.operations if body else None
    try:
        upstream_capture.enable(operations)
    except Exception as exc:
        log.warning("upstream capture enable failed rid=%s: %s",
                    _rid(request), sanitize_error(str(exc)))
        return _json(503, "spectre_error", "Could not install the upstream capture hook")
    await _audit(request, "upstream_capture_enable",
                 f"operations={','.join(operations) if operations else 'all'}")
    return upstream_capture.summary()


@router.get("/api/upstream-capture", dependencies=[Depends(require_admin_access)])
async def get_upstream_capture(request: Request):
    """Return the current capture state and any buffered entries (newest first)."""
    result = upstream_capture.summary()
    result["entries"] = upstream_capture.snapshot()
    return result


@router.delete("/api/upstream-capture", dependencies=[Depends(require_admin_access)])
async def disable_upstream_capture(request: Request):
    """Disable capture and clear the buffer."""
    await anti_csrf(request)
    upstream_capture.disable()
    await _audit(request, "upstream_capture_disable")
    return upstream_capture.summary()
