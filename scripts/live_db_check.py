"""One-off live connectivity check for TiDB (primary) + CockroachDB (backup).
Run manually: python scripts/live_db_check.py
Not part of pytest: uses real external services."""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Windows + Proactor + TLS sockets can fail with WinError 87 in aiomysql's
# handshake; the selector loop avoids it. (Render/Linux is unaffected.)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from app.db import AccountStore  # noqa: E402
from app.logging_setup import sanitize_error, setup_logging  # noqa: E402

TIDB = os.environ.get("TIDB_URL", "")
CRDB = os.environ.get("CRDB_URL", "")


async def probe(url: str, label: str) -> AccountStore | None:
    print(f"--- {label} ---")
    store = AccountStore(url, label=label)
    try:
        await store.connect()
        await store.init_schema()
        ok = await store.ping()
        print(f"connected backend={store.backend} ping={ok}")
        await store.upsert_account("__probe__", "ENC-PROBE-A", "ENC-PROBE-B", enabled=False)
        metas = await store.list_accounts_meta()
        print("accounts:", [m["label"] for m in metas])
        flags = await store.list_tool_flags()
        print("tool_flags:", len(flags))
        usage = await store.list_tool_usage(limit=3)
        print("usage rows:", len(usage))
        removed = await store.delete_account("__probe__")
        print("cleanup:", removed)
        return store
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {sanitize_error(str(exc))}")
        try:
            await store.close()
        except Exception:
            pass
        return None


async def backup_roundtrip(primary: AccountStore, backup: AccountStore) -> None:
    print("--- backup roundtrip ---")
    await primary.upsert_account("__bk_test__", "ENC-BK-A", "ENC-BK-B", enabled=True)
    from app.backup import BackupManager
    from app.models import GatewayState

    mgr = BackupManager(backup, GatewayState())
    mgr.bind_primary(primary)
    result = await mgr.run(triggered_by="live-test")
    print("backup result:", result)
    rows = await backup.dump_accounts()
    print("backup accounts:", [r["label"] for r in rows])
    await primary.delete_account("__bk_test__")
    await backup.delete_account("__bk_test__")
    print("cleanup done")


async def main() -> int:
    setup_logging("WARNING")
    if not TIDB or not CRDB:
        print("set TIDB_URL and CRDB_URL env vars")
        return 2
    primary = await probe(TIDB, "primary/TiDB")
    backup = await probe(CRDB, "backup/CockroachDB")
    rc = 0
    if primary is None or backup is None:
        rc = 1
    else:
        await backup_roundtrip(primary, backup)
        await primary.close()
        await backup.close()
    print("RESULT:", "OK" if rc == 0 else "FAILED")
    return rc


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
