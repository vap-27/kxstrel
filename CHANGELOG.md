# Changelog

All notable changes to this gateway are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-09-15

Rebrand release. The product is now **Kxstrel X MCP** - a naming change only; no runtime behaviour changed. Two of the renamed identifiers are operationally visible, and they are called out below.

### Changed

- Rebranded from `x-mcp` to **Kxstrel X MCP** (identifier slug
  `kxstrel-x-mcp`). The display name reaches the console title and brand, the
  FastAPI title, and `APP_NAME` - so `/health`, `/status` and `/diagnostics`
  report it. Machine identifiers use the slug instead: logger names are now
  `kxstrel-x-mcp.<module>` and the image workdir is `/srv/kxstrel-x-mcp`.
  Deliberately **unchanged**: the Render service name (`render.yaml` `name:`)
  and the live hostnames, because renaming a live service identity would create
  a new service and a new URL; and database names, which are parsed from the DSN
  rather than derived from the brand.
- Every remaining `xmcp` identifier was renamed to `kxstrel` too: the
  Prometheus metric names (`kxstrel_http_requests_total`,
  `kxstrel_tool_calls_total`, `kxstrel_admin_actions_total`,
  `kxstrel_tool_duration_ms`, `kxstrel_x_session_ok`, `kxstrel_db_ok`), the
  admin session cookie and its Redis key prefix, the console theme storage key,
  the `KXSTREL_*` script environment variables, the internal registry
  attributes, and the sample database names. Two operational consequences:
  any dashboard or alert referencing the old metric names must be updated, and
  existing admin sessions are invalidated by the cookie and Redis-key change,
  so operators sign in once more.

## [2.0.0] - 2026-09-14

The hardening release. The gateway is still one FastAPI process exposing the
pinned `spectre-mcp==1.0.3` server over remote Streamable HTTP with no browser
anywhere in the chain; this pass makes the authentication surface
self-describing, rebuilds the admin console, gives operators a probe and
verification toolchain, and makes the storage layer portable across TiDB
(MySQL), Postgres, CockroachDB and SQLite.

### Added

- Two narrow, **read-only** snapshot fallbacks for accounts that cannot be
  used. If the primary store is unreachable or holds no account row at all,
  the Spectre pool is hydrated from the newest snapshot (`restored_from_snapshot`
  in `/status`, `/diagnostics` and the console); if a stored credential cannot
  be decrypted, the newest snapshot's row for that same label is tried before
  the account is reported `CONFIG_ERROR` (`x_session.restored_labels`). A
  primary that holds accounts — even all disabled — stays authoritative, and
  neither path writes to the primary store.
- `POST /admin/api/backup/restore` (admin auth + the CSRF guard, plus a
  per-row **Restore** button in the console's Backup view) writes a snapshot
  back into the primary store — newest by default, an explicit `snapshot_at`
  otherwise. It upserts and resurrects accounts (never deleting those that
  exist only on the primary), re-applies tool flags, re-inserts audit rows
  idempotently and re-hydrates the pool afterwards. This is the only path
  that writes a snapshot into the primary, so resurrecting a deleted account
  stays deliberate; validation merely reporting an expired session never
  swaps in older cookies (see `docs/backup-restore.md`).

- Result enrichment in the tool middleware, starting with `schedule_tweet`:
  its result now carries `scheduled_id` plus `scheduled_id_note`, recovered
  from the `get_scheduled_tweets` listing. Spectre 1.0.3 discards the
  CreateScheduledTweet response and never returns the id of the tweet it
  created, so `edit_scheduled_tweet` / `delete_scheduled_tweet` (which need
  `scheduled_id` / `tweet_id`) could not be driven from the result at all.
  The added field is gateway-produced and labelled as such; it is appended
  only when exactly one listed entry matches the created tweet's text and
  execution time (upstream reports seconds, the listing milliseconds), and
  any failure, ambiguity or unreadable listing leaves the upstream result
  untouched — enrichment is best-effort and never fails a call. Enrichers
  live in an explicit `TOOL_ENRICHERS` table. The two upstream gaps that
  cannot be repaired this way (`create_bookmark_folder` answering
  `folder_id: null` without creating a folder, `create_highlight` exposing no
  highlight id) are documented as known limitations in the README and
  `docs/invocation.md`.
- An admin-gated **upstream GraphQL response capture**, off by default, added
  to diagnose the tools below that report success without evidence. A single
  process-local wrapper around the writer's `_post` choke point records the
  operation, the request variables and the parsed response into a bounded
  in-memory ring buffer (`POST` / `GET` / `DELETE /admin/api/upstream-capture`,
  admin auth plus the CSRF guard). It is a pure pass-through - identical
  return value, exceptions and timing whether wrapped or not - stores redacted
  values only, never records headers, cookies or transport bodies, and resets
  with the process. Enabling installs the wrapper lazily; disabling clears the
  buffer.

- OAuth discovery endpoints, so a spec-compliant MCP client fails fast and
  legibly instead of walking discovery into Dynamic Client Registration:
  `/.well-known/oauth-protected-resource` (and the `/mcp`-suffixed variant)
  returns RFC 9728 protected-resource metadata declaring
  `bearer_methods_supported: ["header"]` with an **empty**
  `authorization_servers`, which tells a client there is no authorization
  server to register with; `/.well-known/oauth-authorization-server`,
  `/register`, `/authorize` and `/token` answer explicitly (HTTP 404 with
  `error: unsupported_authorization_server` and the static-bearer
  explanation) instead of a bare `{"detail":"Not Found"}`.
- `WWW-Authenticate: Bearer ... resource_metadata="..."` on the 401 for an
  unauthenticated `/mcp` request, pointing at that metadata.
- `scripts/live_mcp_probe.py`: an end-to-end probe that initialises a
  Streamable HTTP session, enumerates tools and calls them against a deployed
  gateway, with redaction of tokens/cookies in its output, cleanup of the
  sessions it opens, and argument validation.
- `scripts/harden_client_config.ps1`: hardened client-config helper for local
  MCP clients (writes the gateway entry, keeps the bearer out of the config
  where the client supports it).
- Operator documentation `docs/invocation.md` and `docs/token-rotation.md`,
  plus the `kxstrel-tweet` skill under `skills/`.
- `--strict-binaries` (or `BROWSERLESS_AUDIT_STRICT=1`) for
  `scripts/audit_browserless.py`: gates on host-scoped browser binaries as
  well as the project scope.
- Dark theme for the admin console with a two-state toggle, `localStorage`
  persistence, `<html data-theme>` applied before first paint, and a
  `prefers-reduced-motion: reduce` block that also beats the theme-change
  transition.
- Audit caller attribution: every admin audit row now records which caller
  acted and by which method (session cookie vs bearer), from the validated
  caller fingerprint — never the token itself.
- Minimum secret strength enforcement at startup, plus a `PUBLIC_BASE_URL`
  usability check (an unusable value is ignored and warned about instead of
  silently mis-advertising the origin).
- Test suite: 67 → 160 → 203 → 226 → 264 → 270 → 272 → 292 → 305 → 322 tests as the items above
  landed, and 23 → 22 files under `tests/` (four single-topic modules merged
  into their thematic neighbours and seven fully subsumed tests removed; no
  unique coverage dropped).

### Changed

- The backup store now keeps **versioned snapshots** instead of mirroring the
  primary in place. Each run appends a new snapshot (an index row in
  `backup_snapshots` keyed by a microsecond UTC timestamp, plus
  `backup_accounts`, `backup_schema_migrations`, `backup_tool_flags` and
  `backup_admin_audit` in the same partition), so a bad state on the primary
  can no longer overwrite the previous good copy — the old design upserted
  every table and delete-reconciled accounts, which is exactly what it did.
  `schema_migrations` is captured too, and the tables the mirror design left
  in the backup store are kept but unused (not dropped).
- Snapshots older than the new `BACKUP_RETENTION_DAYS` (default 10, minimum
  1 day) are pruned after each successful run: child rows first, then the
  index row, and orphan rows whose index row already vanished are swept as
  well. A pruning failure is logged and surfaced as `prune_error` but never
  fails the run. `BackupManager.run()` now reports the snapshot timestamp,
  the per-table row counts, how many snapshots were pruned and the oldest one
  kept.

- The admin console's theme control is now a three-way labelled segmented
  group — **System** (the new default), **Light**, **Dark** — of three plain
  buttons whose state lives in `aria-pressed`, on both the sign-in card and
  the sidebar. System mode *removes* `<html data-theme>` instead of naming a
  palette, so the stylesheet's `prefers-color-scheme` block governs and the
  console follows the OS **live** (a `matchMedia` `change` listener, with the
  legacy `addListener` fallback) rather than only at first paint. An explicit
  light/dark choice still wins over the OS; a missing, throwing or unusable
  `matchMedia` and a blocked `localStorage` resolve to light instead of
  leaving the console unthemed; and the `kxstrel-theme` key only ever holds
  `system`, `light` or `dark`.
- README rewritten around the operational reality, and its **Known
  Limitations** section now records the *confirmed* cause of each
  silently-succeeding tool instead of leaving them unexplained. The causes were
  established by capturing X's raw GraphQL replies with the new capture hook:
  bookmark collections answer `AuthorizationError` code 37, "User is not
  authorized to use bookmark collections", for both create and list; highlights
  answer `tweet_highlights_put: {"success": false, "message": "user is not
  eligible to highlight tweet"}`; and `delete_highlight` is broken in two
  independent ways - it sends the GraphQL variable `highlightId` where X
  requires `tweet_id` (X replies `GRAPHQL_VALIDATION_FAILED`), and it discards
  that reply and answers `{"status":"deleted"}` regardless. The first two are
  account permissions on X's side and cannot be repaired here; the third
  cannot be repaired without modifying the pinned package. A `created` /
  `added` / `deleted` status from those tools is therefore **not** proof that
  anything happened - verify with a follow-up read.
- The README also records an **unverified** item rather than implying a fix:
  follow / block / mute / DM-block calls report success while the account's own
  counters and lists do not reflect the change (a successful `follow_user`
  left `friends_count` unchanged at 5 and `get_following` empty). Whether the
  write is dropped or the read path is stale was not determined, because the
  capture hook does not intercept that path.

- Admin console rebuilt as a light-theme operations console, preserved through
  the later dark theme: system-only font stack, inline monoline SVG icons, no
  emoji, no gradients, no remote assets, and the existing strict CSP
  (`default-src 'none'`, no inline styles) unchanged.
- `scripts/audit_browserless.py` scope split, which is what turned CI green:
  project-scoped checks (manifests, sources, installed distributions) are hard
  failures, host-scoped observations (browser executables on `PATH`, running
  browser processes) are informational notes that never gate the exit code —
  unless `--strict-binaries` is passed.
- `scripts/smoke_test.py` strengthened (explicit envelope/status assertions
  and redaction checks rather than presence-only checks).
- `render.yaml` asks the operator for every environment variable it declares:
  `LOG_LEVEL` and `SESSION_CHECK_INTERVAL_SECONDS` no longer ship hardcoded
  `value:` defaults, which silently overrode whatever was set in the Render
  dashboard. `DATABASE_URL`, `BACKUP_DATABASE_URL`, `MCP_ACCESS_TOKEN`,
  `ADMIN_TOKEN`, `CREDENTIAL_ENCRYPTION_KEY`, `PUBLIC_BASE_URL` and
  `REDIS_URL` were already operator-entered.
- `scripts/verify_deployment.py` accepts `backup_ok: null` (a deployment that
  has not run its first backup yet is not a failure).
- The admin dashboard filters test client names, and the WRITE tool pill uses
  the calm blue rather than a red accent.

### Fixed

- **Migrations no longer depend on a vendor advisory lock.** The runner called
  `pg_advisory_lock()`, which CockroachDB does not implement, so the backup
  store — a CockroachDB database — failed to initialise with
  `startup: backup store unavailable: unknown function: pg_advisory_lock()`
  and scheduled backups silently never ran. Every engine now claims each
  version through the `schema_migrations` primary key
  (`INSERT ... ON CONFLICT DO NOTHING` / `ON DUPLICATE KEY` no-op), runs the
  DDL only if the claim was won, and settles the row afterwards; a failed run
  releases its claim instead of marking the version applied.
- **Postgres parameter binding restored in `AccountStore._exec`.** The
  statement rewrite produced `$1..$n` placeholders but the bound arguments
  were dropped, so every parameterized write failed on asyncpg — Postgres and
  the CockroachDB backup mirror included. A stub-driver test now pins the
  arity and order of the bound arguments for every write path.
- SQLite connections are closed deterministically. The `sqlite3` context
  manager commits but never closes, so long-running processes leaked one file
  descriptor per statement.
- Statement splitting and the `?` → `$n` rewrite are quote-aware: `;` and `?`
  inside string literals, quoted identifiers and comments are ignored, and
  input that cannot be scanned safely (unterminated literal/comment) is
  refused instead of guessed at. MySQL's backslash escapes are honoured in the
  MySQL dialect only.
- Admin sessions are bound to a non-reversible `ADMIN_TOKEN` fingerprint, so
  rotating the token invalidates existing sessions; records without a
  fingerprint never validate.
- The nested `file_path` block is genuinely recursive: a `file_path` key
  buried in a nested argument payload can no longer reach the media upload
  tools.
- The client registry bounds the per-client version list (and counts the
  overflow), so a client reporting endless `clientInfo` versions from the wire
  cannot grow it without limit.

### Security

- Every protected admin route declares `require_admin_access`, and a
  structural test asserts it (including that public routes are the only
  exceptions).
- Public admin paths are matched exactly
  (`/admin/api/login`, `/admin/api/session`), so lookalikes such as
  `/admin/api/loginSteal` are not public.
- Rate limiting for `/tools`, `/diagnostics` and `/metrics` on a shared
  per-caller budget that does not depend on their own auth checks.
- The `/admin` budget no longer covers `/admin/assets/*`: a browser fetching
  HTML, CSS and JS on every page load used to exhaust the budget and be served
  the 429 JSON body as its stylesheet/script, i.e. a blank console. The files
  are public and credential-free, so nothing brute-forceable was exempted.
- Tool policy is a security boundary: an authenticated MCP request is refused
  with `503 policy_unavailable` when the policy database did not come up,
  rather than reaching the unwrapped Spectre app.
- Rate-limit keys use the rightmost `X-Forwarded-For` entry (the one the
  trusted edge proxy appends), so callers cannot rotate their own bucket.
- Credential-shaped values (bearer tokens, cookies, URL passwords) are
  redacted from logs and error payloads by the existing
  `sanitize_error`/`redact` discipline, which the new endpoints, probe and
  audit rows all route through.

### Removed

- The `pg_advisory_lock` / `GET_LOCK` migration locks and their constants
  (with the MySQL-only "one statement per migration" restriction they
  implied). The primary-key claim replaces both and is what actually prevents
  two instances applying the same migration.
- Probe transcripts are no longer tracked in version control: they are
  operator-local and contain live X response data.

## [1.0.0] - 2026-09-12

Baseline: a remote MCP gateway in front of the pinned `spectre-mcp==1.0.3`
server (X/Twitter GraphQL/REST with cookie auth), plus a self-hosted admin
console.

- Remote MCP endpoint at `POST /mcp` over Streamable HTTP, mounted from
  Spectre's FastMCP app, with idle session expiry and no browser in the chain
  (no Chromium/Puppeteer/Playwright/Selenium anywhere in the tree).
- Authentication: a static bearer `MCP_ACCESS_TOKEN` for the MCP and
  diagnostics surface, and a separate `ADMIN_TOKEN` for the console; static
  secrets refused when obviously weak.
- Storage: a primary store on TiDB (MySQL), Postgres or SQLite holding
  encrypted account credentials, tool flags, usage logs and the admin audit
  trail; optional Postgres-compatible backup store for scheduled mirrors.
- Admin dashboard: login, account setup/validation/toggle/delete, tool flags,
  usage log, audit trail, client list, on-demand backup trigger, metrics.
- Credentials encrypted at rest with `CREDENTIAL_ENCRYPTION_KEY`; only
  ciphertext is stored and list APIs return redacted metadata.
- Operations: `/health`, `/status`, `/tools`, `/diagnostics`, `/metrics`,
  rate limiting, request-size limits, request IDs, structured
  secret-redacting logs, and a browserless audit script wired into CI.
