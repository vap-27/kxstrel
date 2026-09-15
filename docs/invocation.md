# Invoking Kxstrel X MCP tools (the working path)

This is the path that has been verified end-to-end: a raw MCP
Streamable-HTTP JSON-RPC session over `POST /mcp`, authenticated with the
gateway bearer token. Model-driven clients (via a stdio bridge) and raw
scripts use the same endpoint and the same token.

- Endpoint: `POST https://<your-host>/mcp` (a locally started instance:
  `http://127.0.0.1:8000/mcp`)
- Headers on **every** request:
  - `Authorization: Bearer <MCP_ACCESS_TOKEN>`
  - `Accept: application/json, text/event-stream`
  - `Content-Type: application/json`
  - after `initialize`: `mcp-session-id: <value from the initialize response>`
- The bearer token is valid for **both** the handshake and `tools/call`. There
  is no separate OAuth token, no scope upgrade, and no second credential: the
  same `MCP_ACCESS_TOKEN` that discovers tools calls them. X session cookies
  are never client credentials and are never accepted here.

## 1. The required sequence

```
1. POST /mcp   initialize                      (with bearer)  -> 200 + mcp-session-id
2. POST /mcp   notifications/initialized       (no id, session header)
3. POST /mcp   tools/list                      -> the installed tool set
4. POST /mcp   tools/call                      -> the real result
```

`initialize` request:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize",
 "params":{"protocolVersion":"2025-06-18","capabilities":{},
           "clientInfo":{"name":"my-client","version":"1.0"}}}
```

`notifications/initialized` is a notification: **no `id` field**, and the
server answers `202 Accepted` with an empty body.

```json
{"jsonrpc":"2.0","method":"notifications/initialized"}
```

Skipping step 2 is a protocol violation; some servers tolerate it, this one
has been verified with it present — keep it.

`tools/call`:

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call",
 "params":{"name":"get_tweet","arguments":{"tweet_id":2098981759962783908}}}
```

## 2. Parsing the response (SSE framing)

Most responses arrive as `text/event-stream`, even for single messages:

```
event: message
data: {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"..."}],"isError":false}}
```

Rules that work:

- Read `Content-Type`. If it contains `text/event-stream`, scan lines:
  - `data: <json>` lines carry the JSON-RPC payload; a message ends at a
    blank line (multiple `data:` lines in one event are joined with `\n`).
  - `event:`, `id:`, `retry:` and `:` (comment/keepalive) lines carry no
    payload — ignore them.
- Otherwise the body is a single JSON document (this happens for
  `notifications/initialized`, which returns an empty 202 body).
- The response body of a `tools/call` is a JSON-RPC envelope. The tool output
  is a **string** at `result.content[0].text` — usually JSON, but always a
  string. `result.isError` is `true` for a failed call.
- A tool may also answer `isError:false` with a payload that itself says
  `{"error": "..."}` (for example `{"error": "User @nasa not found"}` when no
  X session is configured). Check the payload, not only `isError`.

Reference implementations: `scripts/live_mcp_probe.py` (full transcript) and
`scripts/smoke_test.py` (minimal client with shape assertions).

## 3. Tool names and argument schemas

Derived from the installed `spectre-mcp==1.0.3` FastMCP server (the gateway
enumerates the same definitions live; `GET /tools` shows the current list).

### `get_tweet`

> Get a single tweet by its ID.

| argument | type | required | notes |
|---|---|---|---|
| `tweet_id` | integer | yes | the **numeric** tweet ID |

```json
{"name":"get_tweet","arguments":{"tweet_id":2098981759962783908}}
```

Turning a tweet URL into the argument: `https://x.com/<user>/status/<ID>` →
`<ID>` is the digits after `/status/`, up to `?`, `#` or `/`
(e.g. `.../status/2098981759962783908/photo/1` → `2098981759962783908`).
Pass it as a JSON number, not a string.

### `search`

> Search X/Twitter for tweets matching a query.

| argument | type | required | default | notes |
|---|---|---|---|---|
| `query` | string | yes | — | supports operators: `from:user`, `since:2026-01-01`, `#tag`, `filter:media`, `lang:en` |
| `limit` | integer | no | `20` | max 100 |
| `mode` | string | no | `latest` | `latest`, `top`, or `media` |

```json
{"name":"search","arguments":{"query":"from:nasa filter:media","limit":5,"mode":"latest"}}
```

Returns a JSON array of tweet objects (`id`, `url`, `text`,
`author_username`, counts, `media_urls`, ...).

### `search_users`

> Search X/Twitter for users by name or keyword.

| argument | type | required | default | notes |
|---|---|---|---|---|
| `query` | string | yes | — | name/keyword, not an @handle |
| `limit` | integer | no | `10` | max 50 |

Returns a JSON array of user profiles (`id`, `username`, `display_name`,
`followers`, ...). An empty array means no match (or no usable X session).

### `get_user`

> Get a user's X/Twitter profile by @handle.

| argument | type | required | notes |
|---|---|---|---|
| `username` | string | yes | handle **without** the leading `@` |

Returns a JSON object with `id`, `username`, `display_name`, `bio`,
`followers`, `following`, `tweets`, `verified`, `profile_image_url`, ...

## 4. MCP clients that speak stdio only (bridge)

Anything that cannot speak Streamable HTTP needs a local bridge. The verified
form pins the bridge version so `npx` cannot drift between cached builds:

```yaml
mcpServers:
  kxstrel-x-mcp:
    enabled: true
    command: npx
    args:
      - "-y"
      - "mcp-remote@0.14.0"          # pinned: must match the verified bridge
      - "https://<your-host>/mcp"
      - "--header"
      - "Authorization: Bearer ${MCP_ACCESS_TOKEN}"
```

**The pinned version must match the bridge behaviour actually verified.**
After changing it, re-run one real call (`scripts/live_mcp_probe.py --live`)
before trusting it. `mcp-remote@0.14.0` is the version this repository was
pinned against; the bridge behaviour itself was not re-executed in this
environment (no npm/network use), so treat the pin as a starting point to
re-verify, not as a guarantee.

If the client config needs hardening (backup, user-only ACL, exact YAML
edits, version pin), use:

```powershell
# dry run (default): prints the edits, changes nothing
.\scripts\harden_client_config.ps1 -ConfigPath "$env:LOCALAPPDATA\hermes\config.yaml"

# apply: timestamped backup + ACL restricted to the current user
.\scripts\harden_client_config.ps1 -ConfigPath "$env:LOCALAPPDATA\hermes\config.yaml" -Apply
```

The helper never writes or prints the token value; keep the token in an
environment variable (`${MCP_ACCESS_TOKEN}`), never inline in the YAML.

## 5. Why clients no longer attempt OAuth

The gateway is header-bearer authenticated and implements no OAuth. It says so
explicitly, without credentials:

| endpoint | response |
|---|---|
| `GET /.well-known/oauth-protected-resource` | `200` with `authorization_servers: []`, `bearer_methods_supported: ["header"]` |
| `GET /.well-known/oauth-protected-resource/mcp` | same, `resource` = `.../mcp` |
| `GET /.well-known/oauth-authorization-server` | `404` `{"error":"unsupported_authorization_server", ...}` |
| `GET/POST /register`, `/authorize`, `/token` | `404` with the same explicit non-OAuth body |

A 401 from `/mcp` also carries
`WWW-Authenticate: Bearer error="invalid_token", resource_metadata=".../.well-known/oauth-protected-resource/mcp"`,
so a spec-compliant client reads the metadata, sees an empty
`authorization_servers` list, and stops instead of attempting Dynamic Client
Registration (which previously died as
`RegistrationRejectedError ... (HTTP 404)`).

## 6. Re-verification procedure (after any token/config change)

```bash
# 1. full transcript, discovery only
python scripts/live_mcp_probe.py --base-url https://<host>

# 2. one REAL tool call, complete exchange written to --out
MCP_ACCESS_TOKEN=... python scripts/live_mcp_probe.py \
    --base-url https://<host> --live --tool get_user --args-json '{"username":"nasa"}' \
    --debug --out probe.json

# 3. deployment smoke test (discovery) and strong variant (real calls + shape checks)
MCP_ACCESS_TOKEN=... ADMIN_TOKEN=... python scripts/smoke_test.py --base-url https://<host>
MCP_ACCESS_TOKEN=... ADMIN_TOKEN=... python scripts/smoke_test.py --base-url https://<host> --live
```

Step 2 is mandatory: discovery alone is what previously hid a broken call
path. See `docs/token-rotation.md` for the rotation procedure.

## 7. Known limitations of the installed tool set

Observed behaviour of the pinned `spectre-mcp==1.0.3` tools, stated as
observed. The last two have no established cause (an upstream restriction is
plausible; it was not investigated further). Nothing here is a defect this
gateway can repair without modifying the installed package.

### `schedule_tweet`: `scheduled_id` is added by the gateway

Upstream returns only:

```json
{"status":"scheduled","execute_at":"2027-05-30T12:00:00Z","execute_at_timestamp":1811851200}
```

— no id, so `edit_scheduled_tweet` (`scheduled_id`) and
`delete_scheduled_tweet` (`tweet_id`) cannot be driven from the result. The
gateway recovers the id from `get_scheduled_tweets` and appends two fields:

```json
{"status":"scheduled","execute_at":"2027-05-30T12:00:00Z","execute_at_timestamp":1811851200,
 "scheduled_id":"2099518124605526016",
 "scheduled_id_note":"recovered by the gateway from get_scheduled_tweets; not returned by the create call"}
```

`scheduled_id` and `scheduled_id_note` are **gateway-added, not native
upstream output** — the note is the provenance marker. Rules the recovery
follows, so a client can reason about what it received:

- the id is appended only when exactly **one** listed entry matches the
  created tweet's text *and* execution time (`execute_at_timestamp` is in
  **seconds** upstream; the listing's `execute_at` is in **milliseconds**);
- zero matches, several matches, an unreadable listing or any error ⇒ the
  response comes back exactly as upstream produced it, unchanged and
  unmarked (enrichment is best-effort and never fails a call). The same is
  true when the listing is read from a different account than the one that
  created the tweet (possible on a multi-account pool that rotates);
- the recovery costs one extra listing call per `schedule_tweet` call, and
  the tool's recorded duration includes it.

### `create_bookmark_folder`: `folder_id: null`, no folder appears

It answers `{"status":"created","folder_id":null,"name":"..."}` while
`get_bookmark_folders` keeps answering `{"folders":[],"count":0}`, and no
folder shows up in the account, so `edit_bookmark_folder` /
`delete_bookmark_folder` have no id to target. Cause not established.

### `create_highlight`: no highlight id is exposed

It answers `{"tweet_id": ..., "status": "added"}` and no installed tool
returns a highlight id (`get_user_highlights` lists tweets, not highlight
ids), so `delete_highlight` cannot be targeted. Cause not established.
- **`delete_highlight` reports success unconditionally.** It always answers
  `{"status":"deleted","highlight_id":<whatever you passed>}` because it never
  inspects the upstream reply, so it returns `deleted` even for a value that
  was never a highlight id (verified by passing a tweet id). A `deleted`
  result from this tool is therefore not evidence that anything was removed.

### Diagnosing the "success but nothing happens" operations

An admin-gated, off-by-default diagnostic captures the raw upstream GraphQL
responses for these operations in-process: `POST /admin/api/upstream-capture`
enables it (optionally restricted to specific operation names),
`GET /admin/api/upstream-capture` returns the buffered entries, and
`DELETE /admin/api/upstream-capture` disables and clears it. It exists only to
inspect X's actual replies; it records nothing until enabled and should be
left disabled outside of an active investigation.
