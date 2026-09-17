## Kxstrel X MCP v2.2.0

Hardened, browserless remote X/Twitter Model Context Protocol (MCP) gateway with native rate limits, instant startup session restoration, and transparent brand logo.

---

### What's Changed

#### [2.2.0] - 2026-09-17
- **Rate Limits Aligned with Upstream X Limits**: Replaced custom gateway throttling with native X rate limits (`RATE_LIMIT_MCP_PER_MIN=1200`). Anti-burst pacing preserved at documented defaults (`max_concurrent_identical=2`, `min_gap=1.5s`, `gap_jitter=3.0s`).
- **Account Pool Cache Renamed**: Renamed local ephemeral SQLite pool cache from `spectre-accounts.db` to `kxstrel-accs.db` across configuration defaults and `Dockerfile`. Added `KXSTREL_DB_PATH` alias support.
- **Instant Startup Session Restoration**: Startup pool hydration now synchronously reads database status (<10ms) and delegates network validation to an asynchronous background task, eliminating false `CONFIG_ERROR` states on fresh boot.
- **MySQL Cursor Warning Suppression**: Filtered benign MySQL 1050 / `already exists` warnings emitted during schema initialization.
- **Admin Console Snapshot Management**: Added backup snapshot deletion with browser confirmation popup, plus live status synchronization.
- **Official Brand Logo**: Integrated high-resolution transparent metallic falcon emblem across GitHub README, admin console header and sidebar, and added official console favicon.
- **PyMySQL 1.2.1 Compatibility**: Pinned `pymysql<1.2.1` in `requirements.txt` and injected runtime fallback for `escape_dict` so `aiomysql` imports reliably across any environment.

---

#### [2.1.0] - 2026-09-15
- **Full Rebrand to Kxstrel X MCP**: Updated display names, FastAPI service title, loggers (`kxstrel-x-mcp`), image workdir, and Prometheus metrics (`kxstrel_*`).
- **Unified Identifier Alignment**: Renamed admin session cookie and Redis key prefix to `kxstrel_admin_session`.

---

#### [2.0.0] - 2026-09-14
- **Hardened Remote MCP Architecture**: Streamable HTTP transport over pinned `spectre-mcp==1.0.3` without browser dependencies.
- **Read-Only Backup Snapshot Fallbacks**: Automatic hydration from newest snapshot when primary store is unreachable or unconfigured.
- **Backup Restore Operation**: `POST /admin/api/backup/restore` allows operators to restore accounts, tool flags, and audit records from backups.
- **Middleware Result Enrichment**: Automatically enriched `schedule_tweet` responses with recovered `scheduled_id`.
- **OAuth Discovery Surface**: Added self-describing RFC 9728 endpoints (`/.well-known/oauth-protected-resource`) to fast-fail OAuth discovery.
- **Live Probe Toolchain**: Included `scripts/live_mcp_probe.py` for automated gateway health testing.

---

### Clean Source Code Distribution
- `kxstrel-v2.2.0.zip` is attached below with zero credentials, zero databases, and zero gitignored/temporary files.
