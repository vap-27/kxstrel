# 🚀 Kxstrel X MCP — Remote X/Twitter MCP Gateway

<p align="center">
  <a href="https://modelcontextprotocol.io/"><img src="https://img.shields.io/badge/MCP-Standard%20v1.0-blue?style=for-the-badge&logo=anthropic" alt="MCP Protocol"></a>
  <a href="https://fastmcp.org/"><img src="https://img.shields.io/badge/FastMCP-Streamable%20HTTP-0ea5e9?style=for-the-badge" alt="FastMCP"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python Version"></a>
  <img src="https://img.shields.io/badge/Architecture-Browserless-10b981?style=for-the-badge" alt="Browserless">
  <img src="https://img.shields.io/badge/Cost-Zero%20Paid%20API-f59e0b?style=for-the-badge" alt="Zero Paid API">
  <a href="https://mermaid.js.org/"><img src="https://img.shields.io/badge/Diagrams-Mermaid-ff3670?style=for-the-badge&logo=mermaid&logoColor=white" alt="Mermaid Diagrams"></a>
  <a href="https://render.com/"><img src="https://img.shields.io/badge/Deploy-Render%20Ready-46e3b7?style=for-the-badge&logo=render" alt="Deploy to Render"></a>
</p>

A hardened, remotely-hosted **Model Context Protocol (MCP)** gateway for X (formerly Twitter). Deploy it once (e.g. on Render) and interface with X from any MCP-compatible AI environment—including **Claude Desktop**, **Claude Code**, **Cursor**, or custom AI agents—without running headless browsers or paying for enterprise API tiers.

---

## 📑 Table of Contents

- [System Architecture](#-system-architecture)
- [Core Architectural Pillars](#-core-architectural-pillars)
  - [1. Why No Official X API Key?](#1-why-no-official-x-api-key)
  - [2. Why No Chromium or Headless Browser?](#2-why-no-chromium-or-headless-browser)
- [How Spectre Engine is Integrated](#-how-spectre-engine-is-integrated)
  - [Tool Safety Classification Matrix](#tool-safety-classification-matrix)
- [Credential Lifecycle & Authentication Flow](#-credential-lifecycle--authentication-flow)
  - [Extracting X Session Credentials (1 Minute)](#extracting-x-session-credentials-1-minute)
- [Quick Start (Local Development)](#-quick-start-local-development)
- [Production Deployment (Render)](#-production-deployment-render)
- [Connecting AI Clients Remotely](#-connecting-ai-clients-remotely)
  - [FastMCP Client (Python)](#fastmcp-client-python)
  - [Claude Desktop / Claude Code / Cursor](#claude-desktop--claude-code--cursor)
- [Admin Dashboard & Telemetry](#-admin-dashboard--telemetry)
- [Storage & Persistence Architecture](#-storage--persistence-architecture)
- [Backup Snapshots & Restore](#-backup-snapshots--restore)
- [Credential Rotation](#-credential-rotation)
- [Security & Threat Model](#-security--threat-model)
- [Known Limitations & Upstream Caveats](#-known-limitations--upstream-caveats)
- [X Rate Limits & How They Are Learned](#x-rate-limits--how-they-are-learned)
- [API Endpoints Reference](#-api-endpoints-reference)
- [Troubleshooting Guide](#-troubleshooting-guide)
- [Self-Verification & Testing](#-self-verification--testing)

---

## 🏛 System Architecture

The gateway acts as an authenticated, rate-limited bridge between external AI clients and internal X GraphQL/REST APIs, utilizing in-process TLS fingerprint emulation.

```mermaid
flowchart TD
    CL1[Claude Desktop / Claude Code] -->|npx mcp-remote@0.14.0| GW[FastAPI Gateway on Render]
    CL2[Cursor IDE] -->|mcp-remote stdio| GW
    CL3[FastMCP Python Client] -->|Streamable HTTP / SSE| GW
    MON[UptimeRobot / Prometheus] -->|GET /health & /metrics| GW

    GW -->|Bearer auth & rate limits| MW[Tool Safety Middleware]
    MW -->|dispatch verified calls| SPEC[Spectre MCP Server: v1.0.3]
    MW -->|block file_path / exfiltration| ERR[400 Bad Request: Call Blocked]

    SPEC --> TW[(Twscrape Pool: /tmp cache)]
    TW -. rebuilt on boot .-> DB

    GW -->|store Fernet encrypted auth_token + ct0| DB[(TiDB / Postgres: Primary DB)]
    DB -. 24h scheduled snapshot .-> BK[(CockroachDB: Backup Store)]
    GW -->|shared admin sessions| RD[(Optional Redis Store)]

    SPEC -->|browserless curl-cffi: chrome120 TLS| X[X Internal Web APIs: GraphQL & REST]
```

---

## 💡 Core Architectural Pillars

### 1. Why No Official X API Key?

Spectre communicates directly with the internal GraphQL and REST endpoints utilized by the official `x.com` web client, authenticated via your personal web-session cookies (`auth_token` + `ct0`).

| Evaluation Dimension | Official X Developer API | Kxstrel X MCP (Spectre Gateway) |
| :--- | :--- | :--- |
| **Pricing** | $100/mo (Basic) to $5,000+/mo (Pro) | **$0.00 (Zero paid subscription required)** |
| **Setup Friction** | Portal application, organization review, OAuth 2.0 PKCE | **1-minute cookie export** from your active browser session |
| **Tool Capabilities** | Restrictive caps on lower tiers | **~104 tools** (Threads, bookmarks, DMs, lists, trends, notes) |
| **Rate Capacity** | Strict monthly read/post buckets | **~300 requests/hour per configured account** |
| **Primary Purpose** | Commercial SaaS & enterprise integrations | **Personal AI automation & agent workflows** |

> [!WARNING]
> **Operational Trade-Offs to Keep in Mind:**
> - Unofficial endpoints can be refactored by X without advance notice.
> - Automated access strictly contravenes X's Terms of Service.
> - Recommended practice: Use a dedicated automation or secondary account, keep check intervals conservative (default 30 min), and avoid spamming write actions.

---

### 2. Why No Chromium or Headless Browser?

No component of the execution flow launches a browser process or renders the DOM. Requests are dispatched over plain HTTP using `curl-cffi` with low-level TLS client fingerprinting matching modern browsers.

| Performance Metric | Headless Browser (Puppeteer / Playwright) | Kxstrel X MCP (`curl-cffi` Gateway) | Advantage |
| :--- | :--- | :--- | :--- |
| **Memory Footprint** | ~200 MB – 600 MB+ per instance | **~10 MB** in memory | **95%+ reduction** (Runs comfortably on free tiers) |
| **Request Latency** | 3 – 10s (Process spin-up, script evaluation, DOM render) | **< 1s** execution per call | **Up to 10x faster response** |
| **DOM Volatility** | High (Breaks whenever frontend class names/HTML change) | **None** (Interacts cleanly with structured JSON APIs) | Superior resilience against frontend styling updates |
| **Host Dependencies** | Heavy binary blobs (`libX11`, `nss`, Chromium binaries) | **Zero browser binaries** (Pure Python + C library) | Ultra-light container images & rapid builds |

#### Automated Browserless Assertion
The build pipeline enforces browserless purity through automated verification:
```bash
python scripts/audit_browserless.py
```
This utility scans manifests, source files, and installed distributions, immediately failing the build if browser stacks (Playwright, Puppeteer, Selenium) are detected.

| Evidence Level | Default Mode | Strict Mode (`--strict-binaries` or `BROWSERLESS_AUDIT_STRICT=1`) |
| :--- | :--- | :--- |
| **Forbidden dependency in requirements/sources** | ❌ **Fail** | ❌ **Fail** |
| **Browser executable on host `PATH`** | ℹ Pass (logged as runner note) | ❌ **Fail** |
| **Active browser process on host** | ℹ Pass (logged as runner note) | ℹ Pass (logged as runner note) |

> [!NOTE]
> `curl-cffi` includes TLS presets named after browsers (e.g. `impersonate="chrome120"`). This represents a cryptographic TLS handshake fingerprint in a standard HTTP client, not a browser engine. The audit script explicitly allowlists this string.
>
> Run the strict audit directly against container images:
> ```bash
> docker run --rm --entrypoint python <image> scripts/audit_browserless.py --strict-binaries
> ```

---

## ⚙ How Spectre Engine is Integrated

- **Pinned Upstream Version**: Strictly locked to `spectre-mcp==1.0.3` in `requirements.txt` (verified: FastMCP stdio server, ~104 tools, dependencies strictly limited to `curl-cffi`, `fastmcp`, `loguru`, `pydantic`, and `twscrape`).
- **Native Mounting**: The gateway imports Spectre's internal `mcp` FastMCP object and exposes it remotely using `mcp.http_app(path="/")` mounted directly at `/mcp` (Streamable HTTP). No tool logic or auth routines are rewritten.
- **Dynamic Introspection**: `GET /tools` inspects the live FastMCP registry (`await mcp.get_tools()`) to report currently installed tools along with read-only vs. destructive indicators.
- **Broad Feature Coverage**: User & tweet search, comprehensive profile metadata, timelines, replies, thread reconstruction, retweeters/favoriters, edit histories, community notes & note rating, trends, lists CRUD, bookmark folders, scheduled tweets, drafts, direct messages (inbox/send/conversations), topic exploration, and mute/block lists.

### Tool Safety Classification Matrix

Tools are stratified into three distinct tiers to safeguard your account:

```mermaid
flowchart TD
    CALL[Incoming Tool Call: POST /mcp] --> CHK1{Hard-blocked tool or file_path?}
    CHK1 -->|Yes: exfiltration risk| BLK[400 Bad Request: Call Blocked]
    CHK1 -->|No: valid arguments| CHK2{Tool enabled in Admin Dashboard?}
    CHK2 -->|No: toggled off| DIS[403 Forbidden: Tool Disabled]
    CHK2 -->|Yes: active tool| CHK3{Action Category}

    CHK3 -->|Read-Only| SAFE[Safe Read Tools: get_*, search_*, list_*]
    CHK3 -->|Write / Destructive| WARN[Destructive Tools: post_tweet, delete, DM]

    SAFE -->|immediate execution| SPEC[Spectre MCP Backend]
    WARN -->|audited execution with warnings| SPEC
```

| Classification | Action Types & Examples | Security Controls & Enforcement |
| :--- | :--- | :--- |
| 🟢 **Read-Only Tools** | `get_user`, `search_tweets`, `get_thread`, `list_bookmarks`, `pool_status` | Safe for automated reasoning loops. No state changes on X. |
| 🟡 **Write / Destructive Tools** | `post_tweet`, `delete_tweet`, `like`, `unlike`, `retweet`, `send_dm`, `follow`, `unfollow` | Flagged with `⚠` descriptions in protocol schemas. Never invoked as a side effect of read actions. Audited in dashboard. |
| 🔴 **Hard-Blocked Tools** | `upload_media`, `update_profile_image`, `update_profile_banner`, `remove_account`, or any call with `file_path` | **Inflexible security block**: Prevent arbitrary server-side file exfiltration. Returns a strict error payload. |

---

## 🔐 Credential Lifecycle & Authentication Flow

Credentials follow an encrypted lifecycle, never exposed over plain logs, URLs, or client-side storage:

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Admin / Developer
    participant Browser as Browser: x.com
    participant Script as setup_account.py CLI
    participant Gateway as FastAPI Gateway
    participant DB as Primary DB: TiDB/Postgres
    participant Twscrape as Spectre Pool: twscrape
    participant X as X Internal APIs

    Admin->>Browser: 1. Inspect Cookies in DevTools F12
    Browser-->>Admin: 2. Copy auth_token and 160-char ct0
    Admin->>Script: 3. Run setup_account.py with hidden input
    Script->>Gateway: 4. POST /admin/account with Bearer ADMIN_TOKEN
    Gateway->>Gateway: 5. Fernet encrypt credentials at rest
    Gateway->>DB: 6. Upsert encrypted account row
    Gateway->>Twscrape: 7. Hydrate in-memory account pool
    Gateway->>X: 8. Validation probe via curl-cffi
    X-->>Gateway: 9. 200 OK: session confirmed active
    Gateway->>DB: 10. Update account status to CONNECTED
    Gateway-->>Script: 11. Success: CONNECTED confirmed
    Script-->>Admin: 12. Gateway ready for AI client traffic
```

### Extracting X Session Credentials (1 Minute)

No automated browser login is required—extract the session cookies directly from your standard browser:

1. Navigate to [x.com](https://x.com) and ensure you are signed in.
2. Open **DevTools** (`F12` or `Ctrl+Shift+I` / `Cmd+Option+I`).
3. Select **Application** (Chrome/Edge) or **Storage** (Firefox) → **Cookies** → `https://x.com`.
4. Copy the values for:
   - **`auth_token`**: Hexadecimal session token string.
   - **`ct0`**: 160-character CSRF token string.

> [!IMPORTANT]
> Always verify that **`ct0`** is exactly 160 characters. Truncated cookies fail silently without producing an explicit authentication error from X.

5. Inject them into your running gateway:
   ```bash
   python scripts/setup_account.py --base-url http://localhost:8000 --label myaccount
   ```
   *(Prompts for credentials using secure hidden inputs; utilizes `ADMIN_TOKEN` from your local `.env`)*

   Alternatively, execute a direct `curl` request:
   ```bash
   curl -X POST http://localhost:8000/admin/account \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"label":"myaccount","auth_token":"YOUR_AUTH_TOKEN","ct0":"YOUR_CT0","enabled":true}'
   ```

---

## 💻 Quick Start (Local Development)

### 1. Environment Setup

```bash
# Clone and enter directory
git clone https://github.com/vap-27/kxstrel.git
cd kxstrel

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create environment configuration
cp .env.example .env
```

### 2. Configure Environment Keys

Generate an encryption key:
```bash
python scripts/setup_account.py --generate-key
```

Add the generated key and custom tokens into your `.env`:
```ini
MCP_ACCESS_TOKEN=your-random-long-secret-for-ai-clients-32chars+
ADMIN_TOKEN=your-random-long-secret-for-admin-ui-32chars+
CREDENTIAL_ENCRYPTION_KEY=your-generated-fernet-key
DATABASE_URL=sqlite:///./data/kxstrel.db
```

### 3. Launch the Gateway

```bash
python -m app.main
# Or run with uvicorn directly:
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
```

> [!NOTE]
> Single worker mode (`--workers 1`) is required because Streamable HTTP MCP client sessions are managed in-process.

---

## ☁ Production Deployment (Render)

### Option A: Render Blueprint (Recommended)

1. Push this repository to your private GitHub repository.
2. Log into [Render Dashboard](https://dashboard.render.com/) → Click **New** → **Blueprint**.
3. Select your repository (`render.yaml` automatically registers the web service).
4. Configure the environment variables in the Render console:

| Variable | Description | Requirement | Example |
| :--- | :--- | :--- | :--- |
| `MCP_ACCESS_TOKEN` | Bearer token used by AI clients to call `/mcp` | **Required** (≥ 32 chars) | `mcp_sec_7f8a9...` |
| `ADMIN_TOKEN` | Secret used to access `/admin` and operational endpoints | **Required** (≥ 32 chars) | `adm_sec_3d2c1...` |
| `CREDENTIAL_ENCRYPTION_KEY` | Fernet key encrypting X cookies at rest in the DB | **Required** | Generated via `setup_account.py --generate-key` |
| `DATABASE_URL` | Production database connection string | **Required** | `mysql://user:pass@gateway01...tidbcloud.com:4000/kxstrel` |
| `BACKUP_DATABASE_URL` | Optional PostgreSQL-compatible backup snapshot store | Optional | `postgres://user:pass@host:5432/kxstrel_backup` |
| `REDIS_URL` | Distributed session cache across restarts | Optional | `redis://default:pass@redis-host:6379` |
| `PUBLIC_BASE_URL` | Canonical URL advertised in protocol metadata | Optional | `https://x-mcp.onrender.com` |

5. Deploy the service. Render completes the Docker build and confirms healthy deployment via `GET /health`.
6. Run the one-time account setup against your live Render domain using `scripts/setup_account.py --base-url https://x-mcp.onrender.com`.

### Option B: Manual Web Service
- **Runtime**: Docker
- **Build Context**: Repo root (`.`)
- **Health Check Path**: `/health`
- **Worker Configuration**: Single process (`--workers 1`)

---

## 🤖 Connecting AI Clients Remotely

Point your MCP client to: `POST https://<your-service>/mcp`  
Set Header: `Authorization: Bearer <MCP_ACCESS_TOKEN>`

### FastMCP Client (Python)

```python
import asyncio
from fastmcp import Client

async def main():
    async with Client("https://x-mcp.onrender.com/mcp", auth="YOUR_MCP_ACCESS_TOKEN") as client:
        # Enumerate live tools
        tools = await client.list_tools()
        print(f"Connected. Available tools: {len(tools)}")
        
        # Invoke a read tool
        result = await client.call_tool("search_users", {"query": "nasa", "limit": 1})
        print(result)

asyncio.run(main())
```

### Claude Desktop / Claude Code / Cursor

For clients that connect over standard I/O (stdio), bridge remote Streamable HTTP using [`mcp-remote`](https://github.com/geelen/mcp-remote):

```json
{
  "mcpServers": {
    "kxstrel-x-mcp": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote@0.14.0",
        "https://x-mcp.onrender.com/mcp",
        "--header",
        "Authorization: Bearer YOUR_MCP_ACCESS_TOKEN"
      ]
    }
  }
}
```

> [!TIP]
> Pin `mcp-remote@0.14.0` as specified above to prevent breaking changes across unpinned `npx` cached builds.
> Run `scripts/harden_client_config.ps1` (PowerShell) on Windows to create a timestamped backup and apply strict user ACLs to your client configuration files.

---

## 🖥 Admin Dashboard & Telemetry

Access the web interface at `https://<your-service>/admin` and sign in with your `ADMIN_TOKEN`.

- **Overview Panel**: Live X session health indicator, primary DB latency, MCP server state, tool counts, and uptime.
- **Usage Telemetry**: Detailed log of every tool execution (tool name, status, duration, client identity, and timestamp). Retained for `USAGE_LOG_RETENTION_DAYS` (default: 30 days).
- **Audit Ledger**: Comprehensive audit records of all admin interventions (logins, session rotations, per-tool switches, on-demand backups).
- **Backup & Restore**: Snapshot list (timestamp, trigger, row counts), an on-demand run, and a per-snapshot **Restore** back into the primary store — see [Backup Snapshots & Restore](#-backup-snapshots--restore).
- **Account Management**: Add, rotate, inspect, validate, or delete X credentials on the fly.
- **Granular Tool Control**: Toggle individual tools on or off with immediate effect in middleware without restarting the gateway.
- **In-Process Tool Playground**: Safely test tool schemas directly from the dashboard UI.
- **Client Handshake Monitor**: Inspect active AI client types (Claude Desktop, Cursor, FastMCP) resolved from MCP `initialize` handshakes.
- **Theme Modes**: System (follows the operating system live), Light and Dark — switchable from both the sign-in screen and the sidebar, persisted locally, with reduced-motion-aware transitions and no external assets.
- **Upstream Response Capture**: Off-by-default, admin-gated diagnostic that records X's raw GraphQL replies for a chosen set of operations — see [Known Limitations & Upstream Caveats](#-known-limitations--upstream-caveats).

### Metrics & Liveness Monitoring

- **Prometheus Metrics (`GET /metrics`)**: Authenticated endpoint exporting request counters, tool latency histograms, and backend connectivity gauges.
- **Uptime Monitoring (e.g. UptimeRobot)**: Monitor `GET https://<your-service>/health`. Returns `HTTP 200` instantly without issuing queries to X or the database, keeping operational noise zero while preventing cold starts.

---

## 🗄 Storage & Persistence Architecture

```mermaid
flowchart LR
    GW[FastAPI Gateway Layer] -->|store encrypted accounts & audit| DB[(Primary DB: TiDB / Postgres / SQLite)]
    GW -->|shared admin sessions| RD[(Optional Redis Store)]

    DB -. 24h scheduled snapshot .-> BK[(Backup DB: CockroachDB)]
    DB -. reconstruct on startup .-> POOL[(Disposable twscrape Pool: /tmp)]

    POOL --> SPEC[Spectre MCP Execution Engine]
```

1. **Primary Store (`DATABASE_URL`)**: TiDB Serverless (MySQL-compatible, 5GB free tier), PostgreSQL, or local SQLite for development. Stores encrypted account records, tool enable/disable flags, pruned usage telemetry, and audit records. Automated schema migrations run on startup (`schema_migrations` table).
2. **Secondary Store (`BACKUP_DATABASE_URL`)**: Optional PostgreSQL-compatible fallback (e.g. CockroachDB Serverless, 10GB free tier). Holds **versioned snapshots** of accounts, `schema_migrations`, tool flags and the audit trail, appended every `BACKUP_INTERVAL_HOURS` (default: 24h) and pruned to `BACKUP_RETENTION_DAYS` (default: 10). See [Backup Snapshots & Restore](#-backup-snapshots--restore).
3. **Disposable Engine Cache (`SPECTRE_DB_PATH`)**: The local twscrape SQLite pool file is treated as completely ephemeral. It is rebuilt cleanly from the encrypted database records upon every cold start.

> [!NOTE]
> **Windows Development Notice**: On Windows systems, the combination of `aiomysql`, the Proactor event loop, and TLS can occasionally raise `WinError 87`. The diagnostics probe `scripts/live_db_check.py` automatically configures the Selector event loop to bypass this Windows platform bug. Linux / Render production environments are unaffected.

---

## 💾 Backup Snapshots & Restore

The optional secondary store keeps an **append-only history**, not a mirror: every run writes a *new* snapshot (accounts incl. their encrypted cookies, `schema_migrations`, tool flags, admin audit) keyed by a microsecond timestamp, so a bad state on the primary can never overwrite the previous good copy. Snapshots older than `BACKUP_RETENTION_DAYS` (default: 10) are pruned after each successful run — child rows first, then the index row, so no orphans are left, and a pruning failure never marks the run as failed.

Two narrow, **read-only** fallbacks put a snapshot to work when an account cannot be used:

| situation | behaviour | reported as |
| :--- | :--- | :--- |
| Primary unreachable, or holds no account row at all | the pool is hydrated from the newest snapshot's accounts so the gateway keeps serving | `restored_from_snapshot` in `/status`, `/diagnostics` and the console |
| A stored credential cannot be **decrypted** | the newest snapshot's row for that same label is tried before the account is reported `CONFIG_ERROR` | `x_session.restored_labels` in `/diagnostics` |
| Validation says the session is **expired / invalid / rate-limited** | **nothing is swapped in.** Expired is expired: reusing older cookies would mask a real outage | status as reported by X |

A primary that holds accounts — even all disabled — is always authoritative, and the automatic fallback never writes to the primary store. Writing a snapshot **back** into the primary is the explicit, admin-only `POST /admin/api/backup/restore` (CSRF-guarded, defaults to the newest snapshot, also available as a per-row **Restore** button in the console): it upserts and resurrects, never deletes, re-inserts audit rows idempotently, and re-hydrates the pool afterwards.

Full operational detail — snapshot tables, retention guarantees, restore procedure — in [`docs/backup-restore.md`](docs/backup-restore.md).

---

## 🔄 Credential Rotation

For full step-by-step procedures and zero-downtime instructions, refer to [`docs/token-rotation.md`](docs/token-rotation.md).

| Secret | Rotation Method | Downtime / Service Impact |
| :--- | :--- | :--- |
| **MCP Access Token** | Update `MCP_ACCESS_TOKEN` in Render → Deploy | Zero downtime. Existing AI clients must update their bearer header. |
| **Admin Secret Token** | Update `ADMIN_TOKEN` in Render → Deploy | Zero downtime. Immediately invalidates all active dashboard sessions. |
| **X Session Cookies** | Re-run `setup_account.py` with fresh cookies | **Zero redeploy, zero restart**. Credentials hot-swap in memory & DB. |
| **Fernet Encryption Key** | Update `CREDENTIAL_ENCRYPTION_KEY` | ⚠ Re-encrypts storage. Requires re-submitting account cookies. |

---

## 🛡 Security & Threat Model

- **Dual-Token Architecture**: AI client invocations (`MCP_ACCESS_TOKEN`) and administration actions (`ADMIN_TOKEN`) are strictly decoupled. X cookies can never be queried or used as gateway bearer tokens.
- **Credential Sanitization**: Automated redaction sweeps all outgoing logs and error objects. Truncated hashes and request IDs (`X-Request-ID`) are surfaced for debugging, keeping raw tokens off console streams.
- **At-Rest Fernet Encryption**: Account credentials in database rows are encrypted using 128-bit AES in CBC mode with HMAC-SHA256 authentication.
- **CSP & Dashboard Security**: The dashboard serves a strict Content Security Policy (`default-src 'none'`), system font stacks (zero external CDN dependencies), strict SameSite session cookies, CSRF header validation (`X-Requested-With`), and `X-Frame-Options: DENY`.
- **Origin Pinning (`PUBLIC_BASE_URL`)**: Eliminates host-header injection attacks by validating incoming origins against an explicit domain whitelist.

---

---

## ⚠ Known Limitations & Upstream Caveats

Observed behaviour of the pinned `spectre-mcp==1.0.3` tool set, verified against a live account by capturing X's raw GraphQL replies. Two entries are X-side restrictions on the account; one is an upstream client defect. They are documented rather than silently patched, because the gateway does not modify the installed package.

| Tool | Observed Behaviour | Cause (verified from X's raw reply) | Fixable here? |
| :--- | :--- | :--- | :--- |
| `schedule_tweet` | Returned `{"status":"scheduled", ...}` with no id, so `edit_scheduled_tweet` / `delete_scheduled_tweet` could not be driven from the result | The upstream client discards the `CreateScheduledTweet` response without inspecting it | ✅ **Repaired.** The gateway recovers the id from `get_scheduled_tweets` and appends `scheduled_id` — see the note below; these fields are **gateway-added, not native** |
| `create_bookmark_folder` | Answers `{"status":"created","folder_id":null}` and no folder ever appears | X returns `AuthorizationError` code 37 — *"User is not authorized to use bookmark collections."* | ❌ Not possible — account-level permission on X |
| `get_bookmark_folders` | Always `{"folders":[],"count":0}` | The same `AuthorizationError`, returned by `BookmarkFoldersSlice` | ❌ Not possible — same permission |
| `edit_bookmark_folder` / `delete_bookmark_folder` | Cannot be called usefully | Both require a `folder_id`, and none is ever issued | ❌ Not possible — no valid target exists |
| `create_highlight` | Answers `{"status":"added"}` and no highlight appears | X returns `tweet_highlights_put: {"success": false, "message": "user is not eligible to highlight tweet"}` | ❌ Not possible — account eligibility on X |
| `delete_highlight` | **Always** answers `{"status":"deleted", ...}`, whatever you pass | Two independent causes: the upstream client sends the GraphQL variable `highlightId` where X requires `tweet_id` (X replies `GRAPHQL_VALIDATION_FAILED`), **and** it discards that reply and reports success regardless | ❌ Not possible without patching the upstream client |

> [!WARNING]
> A `"created"` / `"added"` / `"deleted"` status from the tools in the table above is **not proof that anything happened.** Three of them report unconditional success without inspecting X's reply. Verify with a follow-up read before relying on one.

> [!NOTE]
> **`schedule_tweet` returns two gateway-added fields.** `scheduled_id`, plus `scheduled_id_note` (`"recovered by the gateway from get_scheduled_tweets; not returned by the create call"`). The id is appended only when exactly one listed entry matches the created tweet's text **and** execution time — upstream `execute_at_timestamp` is in seconds, the listing's `execute_at` is in milliseconds. Zero matches, several matches, an unreadable listing, or any error leave the response exactly as upstream returned it. Enrichment is best-effort and can never fail a call.

### Diagnosing upstream behaviour

Because several tools report success without evidence, the gateway ships an **admin-gated raw-response capture** so you can inspect what X actually replied instead of guessing. It is **disabled by default**, in-memory only, resets on restart, and never records headers, cookies or transport bodies.

```bash
# Enable (optionally restrict to specific GraphQL operations)
curl -X POST https://<your-service>/admin/api/upstream-capture \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"operations":["createBookmarkFolder","CreateHighlight"]}'

# Read what X actually returned
curl https://<your-service>/admin/api/upstream-capture \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Disable and clear the buffer
curl -X DELETE https://<your-service>/admin/api/upstream-capture \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

> [!CAUTION]
> Leave this disabled outside an active investigation. While enabled it wraps the upstream GraphQL choke point for the lifetime of the process and records request variables and responses (redacted, but still operational data). Disabling clears the buffer.

### Unverified

- **Follow / block / mute / DM-block calls report success, but the account's own counters and lists did not reflect the change.** In testing, a successful `follow_user` left `friends_count` unchanged (5 → 5) and `get_following` empty. Whether the write is silently dropped or the read path is stale could not be determined — the capture hook does not intercept that path. Treat these as **unverified**, not confirmed broken.

## 📋 API Endpoints Reference

| Method & Route | Authentication | Rate Limit | Purpose & Response Details |
| :--- | :--- | :--- | :--- |
| `POST /mcp` | Bearer (`MCP_ACCESS_TOKEN`) | 120 / min | Remote Streamable HTTP MCP endpoint (supports SSE stream & tool dispatch) |
| `GET /tools` | Bearer (`MCP_ACCESS_TOKEN`) | 120 / min | Live introspection of all registered Spectre tools with read/destructive flags |
| `GET /health` | None | None | Liveness health probe for Render / UptimeRobot (Returns `200 OK` when alive) |
| `GET /status` | None | 60 / min | Public operational check: returns `x_status`, tool count, and versions |
| `GET /diagnostics` | Bearer (`MCP_ACCESS_TOKEN`) | 30 / min | Diagnostic metrics (Spectre status, database connectivity, backup status) |
| `GET /admin` | Session Cookie | 30 / min | Built-in administrative dashboard user interface |
| `POST /admin/api/login` | Token in Request Body | 5 / min | Exchanges `ADMIN_TOKEN` for an encrypted, HttpOnly session cookie |
| `POST /admin/account` | Bearer (`ADMIN_TOKEN`) | 10 / min | Programmatic credential setup & rotation endpoint (used by CLI script) |
| `GET /admin/accounts` | Admin Auth | 30 / min | Returns sanitized metadata for all configured accounts |
| `DELETE /admin/account/{lbl}`| Admin Auth | 10 / min | Purges account credentials from persistent storage and twscrape pool |
| `POST /admin/validate` | Admin Auth | 5 / min | Dispatches an on-demand validation probe against X endpoints |
| `GET /metrics` | Admin Auth | 60 / min | Prometheus telemetry format (counters, histograms, gauges) |
| `GET /.well-known/oauth-protected-resource` | None | None | Returns empty authorization server block, preventing erroneous dynamic client registration |
| `GET /.well-known/oauth-protected-resource/mcp` | None | None | MCP-scoped variant of the same metadata |
| `.well-known/oauth-authorization-server`, `/register`, `/authorize`, `/token` | None | None | Explicit non-OAuth JSON 404s — the gateway issues no client registrations |
| `POST /admin/api/upstream-capture` | Admin Auth | 30 / min | Enables the raw upstream-response capture (admin + CSRF); optional `operations` filter |
| `GET /admin/api/upstream-capture` | Admin Auth | 30 / min | Returns capture state and the buffered upstream entries |
| `DELETE /admin/api/upstream-capture` | Admin Auth | 30 / min | Disables the capture and clears the buffer |
| `POST /admin/api/backup` | Admin Auth | 30 / min | Runs a backup now; appends a new snapshot and prunes past `BACKUP_RETENTION_DAYS` |
| `POST /admin/api/backup/restore` | Admin Auth | 30 / min | Restores a snapshot into the primary store (admin + CSRF); newest by default, `{"snapshot_at": …}` for a specific one |

### Gateway Status Life-Cycle (`x_status`)
- `CONNECTED` — Session authenticated and operational against X APIs.
- `NOT_CONFIGURED` — Server is waiting for initial account cookies.
- `INVALID_SESSION` — Stale or expired cookies (`auth_token` / `ct0`). Requires cookie re-import.
- `RATE_LIMITED` — Upstream threshold reached (~300 req/hour). Automatically clears over time.
- `X_UNAVAILABLE` — Upstream X outage or protocol change.
- `CONFIG_ERROR` — Missing encryption key or unreachable database.

---

## X Rate Limits & How They Are Learned

X applies a per-endpoint request budget. **This gateway does not declare or
enforce those limits**, and it contains no limit table. The transport
(`twscrape`) reads the live values off every response and backs off
accordingly:

| Response header          | Meaning                                |
| :----------------------- | :------------------------------------- |
| `x-rate-limit-limit`     | Requests allowed in the current window |
| `x-rate-limit-remaining` | Requests left in the window            |
| `x-rate-limit-reset`     | When the window resets                 |

Because the real budget is per account and X changes it without notice,
**treat the numbers below as indicative, not authoritative.** They are
community-reported figures - they originate from the Twikit library, which this
project does not use - and have **not** been verified against this deployment.
The mapping from our tool names to the underlying calls *is* taken from the
installed source.

| Our tool              | Underlying call                     | Community-reported limit / 15 min |
| :-------------------- | :---------------------------------- | --------------------------------: |
| `get_tweet`           | `TweetDetail`                       |                               150 |
| `search`              | `SearchTimeline`                    |                                50 |
| `search_users`        | `SearchTimeline`                    |                                50 |
| `get_trends`          | `guide.json`                        |                            20,000 |
| `get_home_timeline`   | `HomeTimeline`                      |                               500 |
| `get_latest_timeline` | `HomeLatestTimeline`                |                               500 |
| `get_user`            | `UserByScreenName` / `UserByRestId` |                               500 |
| `get_followers`       | `Followers`                         |                                50 |
| `get_following`       | `Following`                         |                               500 |
| `get_retweeters`      | `Retweeters`                        |                               500 |
| `get_favoriters`      | `Favoriters`                        |                               500 |

> [!NOTE]
> The restrictive entries are the ones to design around: `search` and
> `search_users` share the `SearchTimeline` budget (50), and `get_followers`
> allows only 50 despite `get_following` allowing 500. Bursts of identical
> calls are also what X's abuse detection reacts to, which is why the gateway
> paces repeated identical tool calls by default
> (`TOOL_MAX_CONCURRENT_IDENTICAL`, `TOOL_MIN_GAP_SECONDS`,
> `TOOL_GAP_JITTER_SECONDS`).

## 🛠 Troubleshooting Guide

| Observed Issue | Diagnostic Cause | Immediate Resolution Step |
| :--- | :--- | :--- |
| `/status` reports `NOT_CONFIGURED` | No X accounts found in database | Execute `python scripts/setup_account.py` to import cookies. |
| `/status` reports `INVALID_SESSION` | Session expired or `ct0` was truncated | Re-copy fresh cookies from `x.com`. Verify `ct0` is exactly 160 characters. |
| `/status` reports `RATE_LIMITED` | ~300 req/hr threshold reached on account | Wait for sliding window to reset, or register a secondary account for auto-rotation. |
| `/status` reports `X_UNAVAILABLE` | Upstream change or outbound network block | Inspect Render console logs. Check if `spectre-mcp` needs an updated pin. |
| `/status` reports `CONFIG_ERROR` | Unreachable DB or bad encryption key | Verify `DATABASE_URL` connectivity and `CREDENTIAL_ENCRYPTION_KEY`. |
| `/health` is 200, but `/mcp` returns 401 | Missing or mismatched bearer token | Check client config matches `MCP_ACCESS_TOKEN` exactly. |
| `/mcp` returns HTTP 429 | Sliding window rate limit exceeded | Back off client request frequency or increase `RATE_LIMIT_MCP_PER_MIN`. |
| `/admin` returns HTTP 403 | Missing `ADMIN_TOKEN` environment key | Set a secure `ADMIN_TOKEN` in `.env` (min 32 characters). |
| Empty search results while `CONNECTED` | Stale session cache on X side | Refresh cookies via `setup_account.py` to clear the silent invalidation. |
| MCP client fails to connect | Client supports only local stdio | Wrap connection with `mcp-remote@0.14.0` bridge via `npx`. |

---

## 🧪 Self-Verification & Testing

Ensure system integrity with the built-in test harness:

```bash
# 1. Run local test suite (Unit + Integration with SQLite)
pytest  # 322 tests passing on a clean checkout

# 2. Assert zero browser/Playwright dependencies in container
python scripts/audit_browserless.py --strict-binaries

# 3. Execute 21-step end-to-end deployment smoke test
MCP_ACCESS_TOKEN="your-token" ADMIN_TOKEN="your-admin-token" \
  python scripts/smoke_test.py --base-url http://localhost:8000 --live

# 4. Inspect full protocol handshake & stream transcript
python scripts/live_mcp_probe.py --live --debug
```

For extended client configuration checklists and protocol specifications, see [`docs/invocation.md`](docs/invocation.md) and [`examples/mcp_clients.md`](examples/mcp_clients.md).
