# Backup snapshots, retention and restore

The gateway keeps its authoritative state in the **primary store**
(`DATABASE_URL`). The optional **backup store** (`BACKUP_DATABASE_URL`,
PostgreSQL-compatible — CockroachDB's free tier is the documented choice)
holds *snapshots* of that state, taken every `BACKUP_INTERVAL_HOURS`
(default 24h) and on demand from the admin console.

A snapshot captures the four tables that matter operationally:

| table | contents |
|---|---|
| `x_accounts` | every account row, including the encrypted `auth_token` / `ct0` |
| `schema_migrations` | which schema version the primary is on |
| `tool_flags` | per-tool enable/disable switches |
| `admin_audit` | the audit trail |

`tool_usage` is deliberately **not** backed up: it is operational telemetry on
the primary and is pruned there by `USAGE_LOG_RETENTION_DAYS`.

Everything below happens in the backup store, never in the primary, except
where explicitly stated.

## 1. Snapshots are append-only

Each run writes a **new** snapshot; nothing is ever updated in place:

| table | key | meaning |
|---|---|---|
| `backup_snapshots` | `snapshot_at` (PK) | one index row per run: timestamp, trigger, row counts |
| `backup_accounts` | `(snapshot_at, label)` | full account rows |
| `backup_schema_migrations` | `(snapshot_at, version)` | the primary's migration state |
| `backup_tool_flags` | `(snapshot_at, tool_name)` | tool switches |
| `backup_admin_audit` | id + `snapshot_at` | audit rows as they were |

`snapshot_at` is a UTC ISO-8601 timestamp **with microseconds**, so two runs
cannot collide; the `backup_snapshots` insert is the run's authoritative
claim and happens before any row of that snapshot is written. If a snapshot's
rows cannot be written, the claim is discarded, so a half snapshot never
exists for the fallback (below) to pick up.

This replaced an in-place mirror that `ON CONFLICT ... DO UPDATE`d every
table: one bad state on the primary would overwrite the previous (good) copy
on the next run. With snapshots, the previous copy is untouchable. The tables
the old mirror design created in the backup store (`x_accounts`, `tool_flags`,
`admin_audit` *there* — migrations 1-4) are **left in place but unused**;
they are not dropped, since a store may still hold the last mirrored copy of
an account.

## 2. Retention

`BACKUP_RETENTION_DAYS` (default **10**, minimum 1 day) bounds the window.
After every successful run the manager deletes each snapshot whose
`snapshot_at` is older than the window:

* child rows first (`backup_accounts`, `backup_schema_migrations`,
  `backup_tool_flags`, `backup_admin_audit`), then the index row, so a crash
  mid-prune can only leave an index row without rows — never an orphan row
  belonging to nothing;
* rows whose index row has already vanished are pruned too, so nothing is
  left orphaned after an interrupted prune;
* the run reports `pruned` (how many snapshots went) and `oldest_snapshot_at`
  (what remains).

**A pruning failure never fails the backup.** The snapshot is already
complete at that point; the failure is logged, surfaced as `prune_error` in
the run result, and the run is still recorded as successful.

## 3. Fallback when the configured accounts cannot be used

Two narrow cases, both **read-only against the primary**:

1. **Store level.** At startup — and on any session check — if the primary
   store is unreachable, or is reachable but holds *no account rows at all*,
   the pool is hydrated from the accounts in the **newest snapshot**. The
   fact is logged loudly and reported as `restored_from_snapshot` (the
   snapshot timestamp, `null` when the primary is authoritative) in
   `/status`, `/diagnostics` and the console.
   A primary that holds accounts, even all disabled, is always authoritative:
   "everything is disabled" is an operator decision, not an outage, and must
   not be silently undone by a snapshot.
2. **One corrupt row.** If a stored credential cannot be *decrypted* (wrong
   key, truncated ciphertext), the newest snapshot's row for that **same
   label** is tried before the account is given up as `CONFIG_ERROR`. Which
   source was used is logged, and the label is listed in
   `/diagnostics` → `x_session.restored_labels`.

### What it deliberately does NOT do

* **No cookie swap on an expired session.** If validation reports the session
  expired/invalid/rate-limited, that is a real outage; the stored (current)
  credential is the only one considered. Silently reusing older cookies from
  a snapshot would hide the outage, keep a stale session in the pool, and
  confuse the operator about which credential is actually in use.
* **No writes to the primary.** The fallback affects the local Spectre pool
  only. It never resurrects a deleted account and never repairs the corrupt
  row it worked around, so the primary keeps reflecting the operator's
  decisions (`/diagnostics` reports the fallback instead).
* **No automatic restore.** See below: putting a snapshot *into* the primary
  is always explicit.

## 4. Restoring a snapshot into the primary

```
POST /admin/api/backup/restore            # newest snapshot
POST /admin/api/backup/restore            # {"snapshot_at": "<timestamp>"}
```

Admin-authenticated (`ADMIN_TOKEN` bearer or dashboard session) and, for
cookie callers, CSRF-guarded with `X-Requested-With: XMLHttpRequest` like
every other mutating admin route. The console's **Backup** view lists the
snapshots and offers a **Restore** button per row.

* accounts in the snapshot are **upserted** (ciphertext as stored; the
  status columns are restored as captured — the next session check re-runs
  validation), which is what resurrects a deleted account;
* accounts that exist **only** on the primary are left alone: a restore
  repairs and resurrects, it never deletes;
* tool flags are re-applied and audit rows re-inserted idempotently (running
  the same restore twice does not duplicate the audit trail);
* afterwards the pool is re-hydrated from the primary with validation off, so
  the restored accounts serve immediately without generating X traffic inside
  the admin request (`pool_hydrated` in the response).

The response reports `snapshot_at`, `accounts`, `tool_flags` and
`admin_audit` counts; every restore is written to the audit trail as
`backup_restore`. Unknown timestamps answer 404, a missing backup store 503.

```bash
curl -sS -X POST https://<host>/admin/api/backup/restore \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"snapshot_at": "2026-09-14T09:15:22.123456+00:00"}'
```

## 5. Verifying

```bash
# one run, and what it pruned
curl -sS -X POST https://<host>/admin/api/backup \
  -H "Authorization: Bearer $ADMIN_TOKEN"
# snapshot list + fallback state, admin-authenticated
curl -sS https://<host>/admin/api/overview -H "Authorization: Bearer $ADMIN_TOKEN"
# public operational view (restored_from_snapshot is here too)
curl -sS https://<host>/status
```
