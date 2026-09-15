"""Remote X/Twitter MCP gateway.

Internet -> FastAPI gateway (auth, rate limits, validation, /mcp, /health,
/status, admin UI) -> spectre MCP/X backend (in-process mount) -> X internal
GraphQL/REST. No browser anywhere in the chain.
"""

from __future__ import annotations

import asyncio
import platform
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse, Response
from starlette.staticfiles import StaticFiles

from app import SPECTRE_PIN, __version__
from .admin_sessions import build_session_store
from .backup import BackupManager
from .config import Settings, get_settings, secret_strength_problems
from .crypto import CredentialCrypto
from .db import AccountStore
from .logging_setup import get_logger, sanitize_error, setup_logging
from .middleware import AuthMiddleware, RequestIdMiddleware, RequestSizeLimitMiddleware
from .models import GatewayState, XStatus
from .rate_limit import RateLimiter
from .routes_admin import require_admin_access, router as admin_router
from .security import external_base_url, is_usable_origin, require_mcp
from .session_monitor import SessionMonitor, aggregate_status
from .spectre_adapter import SpectreAdapter, check_spectre_pin
from . import client_registry
from . import db_resilience
from . import tool_middleware

log = get_logger("kxstrel-x-mcp")

# ── OAuth-declination surface ────────────────────────────────────────────
# The gateway is header-bearer authenticated and implements no OAuth. These
# endpoints make that self-describing so an MCP client fails fast and
# legibly instead of walking OAuth discovery into Dynamic Client
# Registration and dying with an opaque 404.
NON_OAUTH_ERROR = "unsupported_authorization_server"
NON_OAUTH_MESSAGE = (
    "This gateway does not implement OAuth and issues no client registrations. "
    "It authenticates every MCP request with a static header bearer token: "
    "Authorization: Bearer <MCP_ACCESS_TOKEN>. Use the token issued by the "
    "gateway operator; there is no authorization server to discover."
)


def _non_oauth_payload(request: Request) -> dict:
    return {
        "error": NON_OAUTH_ERROR,
        "error_description": NON_OAUTH_MESSAGE,
        "authentication": "header_bearer_static_token",
        "authorization_servers": [],
        "registration_endpoint": None,
    }


def _protected_resource_metadata(settings: Settings, resource: str) -> dict:
    """RFC 9728 protected-resource metadata for a header-token resource.

    `authorization_servers` is deliberately EMPTY: a spec-compliant client
    concludes there is no OAuth authorization server to register with and
    stops before attempting DCR. `bearer_methods_supported: ["header"]`
    declares that the bearer token travels in the Authorization header
    (RFC 6750 §2.1) — no OAuth flow, no browser involved.
    """
    return {
        "resource": resource,
        "resource_name": settings.APP_NAME,
        "authorization_servers": [],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [],
        "authentication": "header_bearer_static_token",
        "service_documentation": "/.well-known/oauth-protected-resource",
    }


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _run_startup_backup(backup_manager: BackupManager) -> None:
    """Run one backup shortly after startup so the dashboard shows a real status."""
    import asyncio as _aio
    try:
        await _aio.sleep(10)  # give DB + adapter a moment to stabilise
        result = await backup_manager.run(triggered_by="startup")
        log.info("startup backup: %s", result)
    except Exception as exc:
        log.debug("startup backup skipped: %s", sanitize_error(str(exc)))


def build_mcp_subapp():
    """Create spectre's Streamable-HTTP ASGI app without modifying spectre.

    A wrapper/adapter is required because spectre ships a stdio MCP server;
    FastMCP's http_app() gives us the remote Streamable HTTP transport with
    the identical, dynamically-enumerated tool set. Idle sessions expire
    after 15 minutes so abandoned clients cannot wedge the session manager.
    """
    from spectre.server import mcp as spectre_mcp

    if hasattr(spectre_mcp, "http_app"):
        try:
            return spectre_mcp.http_app(path="/", session_idle_timeout=900)
        except TypeError:
            return spectre_mcp.http_app(path="/")
    if hasattr(spectre_mcp, "streamable_http_app"):
        try:
            return spectre_mcp.streamable_http_app()
        except TypeError:
            return spectre_mcp.streamable_http_app(path="/")
    raise RuntimeError("installed spectre exposes neither http_app nor streamable_http_app")


async def _enter_mcp_lifespan(stack: AsyncExitStack, mcp_app, state: GatewayState) -> None:
    """Nested lifespans don't run automatically — enter spectre's manually."""
    try:
        lifespan_fn = getattr(mcp_app, "lifespan", None)
        if callable(lifespan_fn):
            await stack.enter_async_context(lifespan_fn(mcp_app))
        else:
            await stack.enter_async_context(mcp_app.router.lifespan_context(mcp_app))
        state.mcp_ok = True
        log.info("spectre MCP sub-app lifespan entered")
    except Exception as exc:
        state.mcp_ok = False
        log.warning("spectre MCP lifespan unavailable (degraded mode): %s", sanitize_error(str(exc)))


def _build_store(settings: Settings, label: str = "primary") -> AccountStore:
    """AccountStore for a DSN, with an unparseable DSN classified and logged.

    A DSN the store cannot even parse is a configuration error, not a
    transient one — no retry can fix it — so it is classified for the log
    (with its actionable hint) and raised, rather than silently retried."""
    url = settings.DATABASE_URL if label == "primary" else settings.BACKUP_DATABASE_URL
    try:
        return AccountStore(url, label=label)
    except Exception as exc:
        kind, hint = db_resilience.classify_db_error(exc)
        log.error("startup: %s database DSN is unusable (kind=%s): %s — %s",
                  label, kind, sanitize_error(f"{type(exc).__name__}: {exc}"), hint)
        raise


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    state: GatewayState = app.state.state

    # -- primary store ----------------------------------------------------
    # connect() + init_schema() run under a bounded, jittered retry. A store
    # that stays unreachable does NOT abort startup: the gateway keeps
    # serving in degraded mode through the existing fallback paths, and the
    # classified failure is exposed by /diagnostics.
    store = _build_store(settings)
    app.state.store = store
    outcome = await db_resilience.connect_and_init(store, settings)
    if outcome.ok:
        state.db_ok = await store.ping()
        state.db_backend = store.backend
        state.db_error_kind = state.db_error = state.db_hint = None
        log.info("startup: database backend=%s ok=%s", store.backend, state.db_ok)
    else:
        state.db_ok = False
        state.db_backend = store.backend  # known even when unusable
        state.db_error_kind = outcome.error_kind
        state.db_error = outcome.message
        state.db_hint = outcome.hint
        log.warning("startup: database unavailable (kind=%s): %s",
                    outcome.error_kind, outcome.message)

    # -- crypto -------------------------------------------------------------
    crypto = None
    if settings.CREDENTIAL_ENCRYPTION_KEY:
        try:
            crypto = CredentialCrypto(settings.CREDENTIAL_ENCRYPTION_KEY)
        except ValueError as exc:
            state.x_status = XStatus.CONFIG_ERROR
            state.last_error = sanitize_error(str(exc))
            log.warning("startup: %s", state.last_error)
    else:
        state.x_status = XStatus.CONFIG_ERROR
        state.last_error = "CREDENTIAL_ENCRYPTION_KEY is not set"
        log.warning("startup: CREDENTIAL_ENCRYPTION_KEY is not set")
    app.state.crypto = crypto

    # -- backup store (optional) --------------------------------------------
    # Same bounded retry as the primary: the snapshot store is a database
    # too, and a cold CockroachDB must not cost the installation its backup
    # manager for the whole process lifetime.
    backup_manager = None
    backup_outcome = None
    if settings.BACKUP_DATABASE_URL:
        backup_store = _build_store(settings, label="backup")
        backup_outcome = await db_resilience.connect_and_init(backup_store, settings)
        if backup_outcome.ok:
            backup_manager = BackupManager(backup_store, state,
                                           retention_days=settings.BACKUP_RETENTION_DAYS)
            backup_manager.bind_primary(store)
            state.backup_backend = backup_store.backend
            log.info("startup: backup store backend=%s ready (retention=%sd)",
                     backup_store.backend, backup_manager.retention_days)
        else:
            log.warning("startup: backup store unavailable (kind=%s): %s",
                        backup_outcome.error_kind, backup_outcome.message)
            try:
                await backup_store.close()
            except Exception:
                pass
    app.state.backup_manager = backup_manager
    app.state.backup_error_kind = backup_outcome.error_kind if backup_outcome else None
    app.state.backup_hint = backup_outcome.hint if backup_outcome else None

    # -- admin sessions (Redis-backed when configured) ------------------------
    try:
        sessions = await build_session_store(settings)
    except Exception as exc:
        log.warning("startup: session store init failed: %s", sanitize_error(str(exc)))
        sessions = None
    app.state.admin_sessions = sessions

    # -- spectre adapter + tool middleware -------------------------------------
    adapter = SpectreAdapter(settings.SPECTRE_DB_PATH)
    app.state.adapter = adapter
    ver, pin_ok = check_spectre_pin()
    state.spectre_version = ver
    state.spectre_pin = SPECTRE_PIN
    state.spectre_version_ok = pin_ok
    if not pin_ok:
        log.warning("startup: spectre-mcp %s != pinned %s; tools enumerated live", ver, SPECTRE_PIN)
    else:
        log.info("startup: spectre-mcp %s (pinned)", ver)

    # -- persisted uptime markers (survive restarts/redeploys/sleep-wake) ----
    if state.db_ok:
        try:
            if await store.get_meta("service_first_started_at") is None:
                await store.set_meta("service_first_started_at", _utcnow())
                log.info("startup: first boot recorded")
            state.service_first_started_at = await store.get_meta("service_first_started_at")
            state.mcp_first_ok_at = await store.get_meta("mcp_first_ok_at")
            state.last_backup_at = await store.get_meta("last_backup_success_at")
        except Exception as exc:
            log.warning("startup: uptime markers unavailable: %s", sanitize_error(str(exc)))

    try:
        tools = await adapter.list_tools()
        state.tool_names = [t["name"] for t in tools]
        state.tool_count = len(tools)
        log.info("startup: spectre exposes %d tools", len(tools))
    except Exception as exc:
        log.warning("startup: tool enumeration failed: %s", sanitize_error(str(exc)))

    if state.db_ok:
        from spectre.server import mcp as spectre_mcp

        app.state.tool_middleware = tool_middleware.attach(spectre_mcp, store, state, settings)
        app.state.client_registry = client_registry.attach(spectre_mcp)
        state.policy_ready = app.state.tool_middleware is not None
    else:
        app.state.tool_middleware = None
        app.state.client_registry = None
        state.policy_ready = False

    # -- monitor (sessions + housekeeping) ------------------------------------
    monitor = SessionMonitor(
        store, crypto, adapter, state,
        settings.SESSION_CHECK_INTERVAL_SECONDS,
        settings.SESSION_CHECK_TIMEOUT_SECONDS,
        backup_manager=backup_manager,
        backup_interval_hours=settings.BACKUP_INTERVAL_HOURS,
        retention_days=settings.USAGE_LOG_RETENTION_DAYS,
    )
    app.state.monitor = monitor
    if sessions is not None:
        monitor.bind_sessions(sessions)

    # -- restore persisted credentials -> pool -> validate --------------------
    # The primary store is authoritative. The backup snapshot is only a
    # fallback for a primary that is unreachable or holds no account at all
    # (see SessionMonitor._accounts_to_serve); it is read-only, never written.
    if crypto is not None and (state.db_ok or backup_manager is not None):
        try:
            if state.db_ok:
                metas = await store.list_accounts_meta()
                state.accounts_configured = len(metas)
                state.accounts_enabled = sum(1 for m in metas if m["enabled"])
            # Always restore the enabled accounts into Spectre's local pool.
            # Validation is optional; persistence restoration is not.
            await monitor.check_once(source="startup", validate=settings.VALIDATE_ON_STARTUP)
        except Exception as exc:
            log.warning("startup: session restore failed: %s", sanitize_error(str(exc)))
            if state.x_status == XStatus.NOT_CONFIGURED:
                state.x_status = XStatus.CONFIG_ERROR
    elif state.x_status != XStatus.CONFIG_ERROR:
        state.x_status = XStatus.CONFIG_ERROR if not state.db_ok else XStatus.NOT_CONFIGURED

    from . import metrics_setup

    metrics_setup.observe_x_status(state.x_status.value)
    metrics_setup.observe_db_ok(state.db_ok)
    await monitor.start()

    # Trigger an initial backup on startup so the dashboard does not show
    # backup_ok=None for the first 24 hours. Runs in the background so it
    # does not block the MCP endpoint from going live.
    startup_backup_task: asyncio.Task | None = None
    if backup_manager is not None:
        startup_backup_task = asyncio.create_task(
            _run_startup_backup(backup_manager), name="startup-backup")

    async with AsyncExitStack() as stack:
        await _enter_mcp_lifespan(stack, app.state.mcp_app, state)
        if state.mcp_ok and state.db_ok and state.mcp_first_ok_at is None:
            # First time the MCP endpoint went live in this installation.
            try:
                await store.set_meta("mcp_first_ok_at", _utcnow())
                state.mcp_first_ok_at = await store.get_meta("mcp_first_ok_at")
                log.info("startup: mcp first-live recorded")
            except Exception as exc:
                log.warning("startup: mcp marker write failed: %s", sanitize_error(str(exc)))
        log.info("startup complete x_status=%s tools=%d", state.x_status.value, state.tool_count)
        try:
            yield
        finally:
            log.info("shutdown started")
            # Stop the pending startup backup BEFORE the stores close: a task
            # waking up mid-shutdown would otherwise run against a closed
            # store and log a spurious failure.
            if startup_backup_task is not None and not startup_backup_task.done():
                startup_backup_task.cancel()
                try:
                    await startup_backup_task
                except (asyncio.CancelledError, Exception):
                    pass
            await monitor.stop()
            for st in (store, getattr(backup_manager, "store", None)):
                if st is not None:
                    try:
                        await st.close()
                    except Exception:
                        pass
            log.info("shutdown complete")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    setup_logging(settings.LOG_LEVEL)

    # Refuse obviously weak secrets at startup rather than serving a
    # guessable token: a short MCP_ACCESS_TOKEN exposes the whole X surface
    # to brute force, a short ADMIN_TOKEN exposes credential management.
    weak = secret_strength_problems(settings)
    if weak:
        raise RuntimeError("refusing to start with weak secrets: " + "; ".join(weak))

    # An unusable PUBLIC_BASE_URL is not fatal (the origin is derived, and
    # safely, per request) but it IS a misconfiguration worth saying out loud:
    # the operator believes the advertised origin is pinned and it is not.
    if settings.PUBLIC_BASE_URL and not is_usable_origin(settings.PUBLIC_BASE_URL):
        log.warning("PUBLIC_BASE_URL is not a bare http(s) origin; ignoring it and "
                    "deriving the advertised origin from each request instead")

    state = GatewayState(started_at=_utcnow())
    mcp_app = build_mcp_subapp()

    app = FastAPI(title="Kxstrel X MCP gateway", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.state = state
    app.state.mcp_app = mcp_app
    app.state.store = None
    app.state.crypto = None
    app.state.monitor = None
    app.state.admin_sessions = None
    app.state.backup_manager = None
    app.state.tool_middleware = None

    # Middleware order: last added runs first.
    origins = ["*"] if settings.ALLOWED_ORIGINS.strip() == "*" else [
        o.strip() for o in settings.ALLOWED_ORIGINS.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["GET", "POST", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept", "Mcp-Session-Id",
                       "Last-Event-ID", "X-Request-ID", "X-Requested-With"],
        allow_credentials=False,
        max_age=86400,
    )
    app.add_middleware(AuthMiddleware, settings=settings,
                       mcp_limiter=RateLimiter(settings.RATE_LIMIT_MCP_PER_MIN),
                       admin_limiter=RateLimiter(settings.RATE_LIMIT_ADMIN_PER_MIN))
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.MAX_REQUEST_BYTES)
    app.add_middleware(RequestIdMiddleware)

    # Remote Streamable HTTP MCP endpoint + static admin assets.
    app.mount("/mcp", mcp_app)
    from .routes_admin import STATIC_DIR

    app.mount("/admin/assets", StaticFiles(directory=str(STATIC_DIR)), name="admin-assets")
    app.include_router(admin_router)

    # -- public operational endpoints ------------------------------------
    @app.get("/health")
    async def health():
        return {"status": "ok", "service": settings.APP_NAME, "version": __version__}

    @app.get("/status")
    async def status():
        s: GatewayState = app.state.state
        uptime = 0.0
        try:
            uptime = (datetime.now(timezone.utc)
                      - datetime.fromisoformat(s.started_at)).total_seconds() if s.started_at else 0.0
        except Exception:
            pass
        from . import metrics_setup

        metrics_setup.observe_x_status(s.x_status.value)
        return {
            "service": settings.APP_NAME,
            "version": __version__,
            "x_status": s.x_status.value,
            "db_ok": s.db_ok,
            "db_backend": s.db_backend,
            "mcp_ok": s.mcp_ok,
            "policy_ready": s.policy_ready,
            "tool_count": s.tool_count,
            "spectre_version": s.spectre_version,
            "spectre_pin": s.spectre_pin,
            "spectre_version_ok": s.spectre_version_ok,
            "accounts_configured": s.accounts_configured,
            "accounts_enabled": s.accounts_enabled,
            "last_checked_at": s.last_checked_at,
            "last_error": s.last_error,
            "service_first_started_at": s.service_first_started_at,
            "mcp_first_ok_at": s.mcp_first_ok_at,
            "backup_ok": s.backup_ok,
            "last_backup_at": s.last_backup_at,
            "last_backup_attempt_at": s.last_backup_attempt_at,
            "last_backup_snapshot_at": s.last_backup_snapshot_at,
            # Snapshot timestamp the pool was hydrated from because the
            # primary store could not provide the accounts; null in the
            # normal, primary-authoritative case.
            "restored_from_snapshot": s.restored_from_snapshot,
            "uptime_seconds": round(uptime, 1),
        }

    # -- authenticated diagnostics (MCP token) ----------------------------
    @app.get("/tools", dependencies=[Depends(require_mcp)])
    async def tools(request: Request):
        """The ACTUAL installed tool list — names, read/write split and
        destructive flags. Never hard-coded."""
        adapter: SpectreAdapter | None = app.state.adapter
        if adapter is None:
            return JSONResponse({"error": {"code": "not_ready",
                                           "message": "Gateway is still starting"}}, status_code=503)
        try:
            tool_list = await adapter.list_tools()
        except Exception as exc:
            log.warning("tool listing failed: %s", sanitize_error(str(exc)))
            return JSONResponse({"error": {"code": "spectre_error",
                                           "message": "Could not enumerate tools"}}, status_code=502)
        return {"count": len(tool_list), "tools": tool_list}

    @app.get("/diagnostics", dependencies=[Depends(require_mcp)])
    async def diagnostics():
        s: GatewayState = app.state.state
        store = app.state.store
        db_ok = await store.ping() if store is not None else False
        pool: dict = {}
        adapter: SpectreAdapter | None = app.state.adapter
        if adapter is not None:
            try:
                pool = await adapter.pool_status()
            except Exception as exc:
                pool = {"error": sanitize_error(str(exc))}
        usage: dict = {}
        if store is not None:
            try:
                usage = await store.usage_summary(days=1)
            except Exception:
                usage = {}
        backup = getattr(app.state.backup_manager, "store", None)
        return {
            "application": {"service": settings.APP_NAME, "version": __version__,
                            "python": platform.python_version(),
                            "debug": settings.DEBUG, "started_at": s.started_at},
            "spectre": {"version": s.spectre_version, "pinned": s.spectre_pin,
                        "version_ok": s.spectre_version_ok, "pool": pool},
            "x_session": {"x_status": s.x_status.value, "last_checked_at": s.last_checked_at,
                          "last_error": s.last_error,
                          "accounts_configured": s.accounts_configured,
                          "accounts_enabled": s.accounts_enabled,
                          "restored_from_snapshot": s.restored_from_snapshot,
                          "restored_labels": list(s.restored_labels)},
            # error_kind + hint say WHY the store is down and what to check.
            # The driver's own text is deliberately NOT echoed here (a driver
            # message can quote the DSN, path included); it is in the startup
            # log, sanitized, where the operator already looks.
            "database": {"backend": s.db_backend, "ok": db_ok,
                         "error_kind": s.db_error_kind,
                         "hint": s.db_hint,
                         "max_attempts": settings.DB_CONNECT_MAX_ATTEMPTS,
                         "base_delay_seconds": settings.DB_CONNECT_BASE_DELAY_SECONDS,
                         "max_delay_seconds": settings.DB_CONNECT_MAX_DELAY_SECONDS},
            "backup": {"configured": app.state.backup_manager is not None,
                       "backend": s.backup_backend, "ok": s.backup_ok,
                       "last_backup_at": s.last_backup_at,
                       "last_backup_error": s.last_backup_error,
                       "last_backup_snapshot_at": s.last_backup_snapshot_at,
                       "retention_days": settings.BACKUP_RETENTION_DAYS,
                       "error_kind": getattr(app.state, "backup_error_kind", None),
                       "hint": getattr(app.state, "backup_hint", None)},
            "mcp": {"ok": s.mcp_ok, "tool_count": s.tool_count,
                    "policy_ready": s.policy_ready,
                    "endpoint": "POST /mcp (Streamable HTTP)"},
            "tool_concurrency": tool_middleware.concurrency_status(
                app.state.tool_middleware, settings),
            "usage_24h": usage,
        }

    # -- MCP auth discovery / OAuth declination ---------------------------
    # Public (no bearer): these must be reachable by an unauthenticated
    # client that is trying to work out HOW to authenticate. They answer
    # with the static, non-OAuth model so discovery terminates immediately
    # and legibly instead of ending in a 404 DCR attempt.
    @app.get("/.well-known/oauth-protected-resource")
    async def oauth_protected_resource_root(request: Request):
        # Same validated origin as the 401 challenge: PUBLIC_BASE_URL wins,
        # a malformed Host/X-Forwarded-Host is dropped.
        return _protected_resource_metadata(settings, external_base_url(request, settings))

    @app.get("/.well-known/oauth-protected-resource/mcp")
    async def oauth_protected_resource_mcp(request: Request):
        return _protected_resource_metadata(
            settings, f"{external_base_url(request, settings)}/mcp")

    @app.get("/.well-known/oauth-authorization-server")
    async def oauth_authorization_server(request: Request):
        # Explicitly absent, with a body that says why (never FastAPI's bare
        # {"detail":"Not Found"}).
        return JSONResponse(_non_oauth_payload(request), status_code=404)

    @app.api_route("/register", methods=["GET", "POST"])
    async def dynamic_client_registration(request: Request):
        # mcp-remote and friends land here after discovery; the explicit
        # body is what makes the failure legible.
        return JSONResponse(_non_oauth_payload(request), status_code=404)

    @app.api_route("/authorize", methods=["GET", "POST"])
    async def oauth_authorize(request: Request):
        return JSONResponse(_non_oauth_payload(request), status_code=404)

    @app.api_route("/token", methods=["GET", "POST"])
    async def oauth_token(request: Request):
        return JSONResponse(_non_oauth_payload(request), status_code=404)

    # -- metrics (admin session cookie or admin bearer) --------------------
    @app.get("/metrics", dependencies=[Depends(require_admin_access)])
    async def metrics():
        from prometheus_client import generate_latest

        return Response(content=generate_latest(), media_type="text/plain; version=0.0.4")

    return app


app = create_app()


def main() -> None:
    import uvicorn

    settings = get_settings()
    # log_config=None keeps our redacting root handler in charge of ALL
    # loggers (uvicorn's own dictConfig would otherwise bypass redaction);
    # access_log off — RequestIdMiddleware already logs requests safely.
    uvicorn.run(app, host=settings.HOST, port=settings.PORT, workers=1,
                timeout_keep_alive=30, access_log=False, log_config=None)


if __name__ == "__main__":
    main()
