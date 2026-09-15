# Token rotation

Two independent secrets guard this service, plus one encryption key:

| secret | guards | rotation effect |
|---|---|---|
| `MCP_ACCESS_TOKEN` | remote MCP clients (`/mcp`, `/tools`, `/diagnostics`) | old token stops authenticating immediately |
| `ADMIN_TOKEN` | `/admin/*` (dashboard login + API) and `/metrics` | old token stops authenticating **and live dashboard sessions are invalidated** |
| `CREDENTIAL_ENCRYPTION_KEY` | stored X session cookies (Fernet) | rotating orphans existing rows — see below |

`MCP_ACCESS_TOKEN` and `ADMIN_TOKEN` are separate secrets and must never be
the same value. X session cookies are never client credentials.

## 1. Generate a replacement

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Minimum length enforced at startup is 32 characters (`app/config.py`,
`MIN_SECRET_LENGTH`). `create_app()` refuses to start on a shorter non-empty
value, so a weak token cannot be deployed silently. `DEBUG=true` does not
relax this: a short dev token is exactly the value that ends up in
production, and generating a strong one is one command.

## 2. Where it is set for the Render deployment

Render dashboard → the Render service (still named `x-mcp`) → **Environment** → edit the variable
→ **Save** (the service redeploys automatically; `autoDeploy: true` in
`render.yaml`). The variables are declared `sync: false` in `render.yaml`, so
their values live only in the Render dashboard, never in the repository.

Local development reads the same names from the environment or `.env`
(`.env.example` documents them). Never commit a filled `.env`.

## 3. Rotate `MCP_ACCESS_TOKEN`

1. Generate the new value (step 1).
2. Update `MCP_ACCESS_TOKEN` in Render and let the service redeploy.
3. Update every client:
   - raw JSON-RPC scripts / probes: pass `--token` or export
     `MCP_ACCESS_TOKEN`,
   - bridge clients (`mcp-remote`): the config should reference
     `${MCP_ACCESS_TOKEN}` from the environment — never inline the value
     (`scripts/harden_client_config.ps1` prints and audits this),
   - the removed old value stops working the moment the new deploy is live.
4. Re-verify (section 6). A green discovery check is not sufficient.

## 4. Rotate `ADMIN_TOKEN`

1. Generate the new value.
2. Update `ADMIN_TOKEN` in Render and redeploy.
3. **Existing dashboard sessions are invalidated.** Sessions are bound to the
   token that created them (the session record stores a non-reversible
   fingerprint of `ADMIN_TOKEN` and `validate()` compares it on every
   request), so after a rotation:
   - every existing `kxstrel_admin_session` cookie stops authorizing (401),
   - the dashboard must log in again with the new token.
   Operators signed in during a rotation will be bounced back to the login
   page — expected, not a bug. `SESSION_TTL_HOURS` (default 8) also bounds
   sessions independently; rotation does not extend or shorten that TTL.
4. Verify with the new token:
   `curl -H "Authorization: Bearer $ADMIN_TOKEN" https://<host>/admin/api/overview`
5. Re-verify the MCP path too if `MCP_ACCESS_TOKEN` was touched in the same
   change window (section 6).

## 5. `CREDENTIAL_ENCRYPTION_KEY` (do not rotate casually)

Rotating it makes existing `x_accounts` ciphertext undecryptable. Procedure:
set the new key, then re-run credential setup for each account (fresh X
cookies) so rows are re-encrypted under the new key. Every client token and
the admin token are unaffected.

## 6. Mandatory re-verification

A discovery-only check once hid a broken call path: the handshake and
`tools/list` were green while no real tool call ever returned data. Never
treat a rotation as complete until a real call succeeded.

```bash
BASE=https://<host>

# 1. discovery + full transcript (no tool call)
python scripts/live_mcp_probe.py --base-url "$BASE" --out probe.json

# 2. one REAL tool call — mandatory
MCP_ACCESS_TOKEN=$NEW_TOKEN python scripts/live_mcp_probe.py \
  --base-url "$BASE" --live --tool get_user \
  --args-json '{"username":"nasa"}' --out probe-live.json

# 3. deployment smoke test with shape assertions on real calls
MCP_ACCESS_TOKEN=$NEW_TOKEN ADMIN_TOKEN=$NEW_ADMIN_TOKEN \
  python scripts/smoke_test.py --base-url "$BASE" --live
```

Expected results:

- `probe.json`: `initialize` → `notifications/initialized` → `tools/list`
  (104 tools on spectre-mcp 1.0.3), exit 0.
- `probe-live.json`: a fourth `tools/call` exchange, exit 0. If the X session
  is unconfigured, the probe reports `UPSTREAM TOOL ERROR ...` and still exits
  0 — that is a *reported* upstream problem, not a broken call path; the
  envelope shape (HTTP 200, `result.content[0].text`, JSON-RPC id match) is
  asserted either way.
- `smoke_test.py --live`: asserts real content — `get_user` must contain
  `id` and `username`, `search_users` must return a non-empty user list. It
  fails loudly on an empty payload or a shape mismatch by design.

## 7. Operational facts to keep in mind

- **Render cold start: 8–12 s measured** on first connect after the free-tier
  instance sleeps. The client timeout in use is **120 s**, which leaves a
  comfortable margin — but if you lower the client timeout below ~30 s, the
  first request after a sleep can time out even though the service is healthy.
  The probe and smoke test default to a 120 s timeout for this reason.
- **`SESSION_TTL_HOURS` (default 8) bounds admin sessions** in addition to the
  token binding; expired sessions are rejected server-side and pruned, and the
  `DELETE /admin/api/sessions` endpoint revokes all live sessions at once
  (scripts using the admin bearer token are unaffected by that revocation).
- **Rate limits** apply per caller: `/mcp` and the metadata endpoints
  (`/tools`, `/diagnostics`, `/metrics`) share the MCP budget
  (`RATE_LIMIT_MCP_PER_MIN`), `/admin/*` has its own
  (`RATE_LIMIT_ADMIN_PER_MIN`). A burst of rotation-verification requests
  from one IP can hit 429 — space them out or raise the limits temporarily.
