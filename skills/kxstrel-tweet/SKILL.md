---
name: kxstrel-tweet
description: Fetch, search, analyze, and interact with X (Twitter) tweets and conversation threads through the Kxstrel X MCP gateway. Use when asked to read, quote, summarize, verify, reconstruct threads, search tweets, or perform governed tweet actions (like, retweet, bookmark, reply, post, schedule).
---

# Tweet Intelligence & Interaction via Kxstrel X MCP (`kxstrel-tweet`)

A comprehensive, production-grade guide for AI agents and developers interacting with X (formerly Twitter) tweets through the **Kxstrel X MCP** gateway. 

The gateway fronts an installed `spectre-mcp==1.0.3` engine running browserless `curl-cffi` TLS fingerprint emulation with `twscrape` pool management over standard Streamable HTTP MCP at `POST /mcp`.

---

## 1. Prerequisites & Gateway Architecture

- **Endpoint**: `POST https://<host>/mcp` (or `http://127.0.0.1:8000/mcp` locally).
- **Authentication**: Static HTTP Bearer header `Authorization: Bearer <MCP_ACCESS_TOKEN>`.
  - The same token is used for protocol initialization, tool enumeration, and tool execution.
  - **No OAuth & No Dynamic Client Registration**: The gateway returns `authorization_servers: []` in metadata; never attempt OAuth handshakes.
- **Account Session Status**: Check `GET /status` → `x_status`. Real operations succeed only when status is `CONNECTED`.
- **Latency & Cold Starts**: On serverless hosts (like Render free tier), cold starts take 8–12 seconds. Ensure client HTTP timeouts are set to **≥ 120s**.
- **Tool Safety Tiers**:
  - 🟢 **Read-Only**: `get_tweet`, `get_thread`, `get_tweet_replies`, `search`, `get_user_tweets`, `get_community_notes`. Safe for autonomous reasoning loops.
  - 🟡 **Write / Destructive**: `post_tweet`, `delete_tweet`, `like_tweet`, `unlike_tweet`, `retweet`, `bookmark_tweet`, `schedule_tweet`. Require explicit user confirmation before execution.
  - 🔴 **Hard-Blocked**: Tools requiring server-local file system access (e.g. `upload_media`, `update_profile_image`) or pool mutation (`remove_account`) are strictly blocked at the gateway level to prevent file exfiltration.

---

## 2. Deterministic Tweet URL & ID Parsing

All tweet reading and interaction tools take a **numeric integer `tweet_id`**, never a URL, handle, or string identifier.

### Parsing Rules

Extract the string of digits immediately following `/status/` (or the query parameter `in_reply_to=` / `tweet_id=`):

| URL Pattern | Extracted Target | Canonical `tweet_id` (Integer) |
|---|---|---|
| `https://x.com/NASA/status/2098981759962783908` | Path status digits | `2098981759962783908` |
| `https://twitter.com/NASA/status/2098981759962783908` | Legacy domain | `2098981759962783908` |
| `https://mobile.twitter.com/NASA/status/2098981759962783908` | Mobile subdomain | `2098981759962783908` |
| `https://x.com/user/status/2098981759962783908/photo/1` | Media subpath stripped | `2098981759962783908` |
| `https://x.com/user/status/2098981759962783908?s=20&t=abc` | Tracking params stripped | `2098981759962783908` |
| `https://x.com/i/web/status/2098981759962783908` | Web redirect format | `2098981759962783908` |

> [!IMPORTANT]
> Always pass `tweet_id` as a **JSON number (integer)**, e.g. `2098981759962783908`. While some clients tolerate quoted string numbers, the schema strictly specifies `integer`.

---

## 3. Tool Reference & Usage Patterns

### A. Single Tweet Inspection: `get_tweet`

Fetches complete metadata, text, author info, media attachments, and engagement metrics for a single tweet.

- **Arguments**:
  - `tweet_id` (*integer*, required): Numeric ID of the tweet.
- **MCP Invocation**:
  ```json
  {
    "name": "get_tweet",
    "arguments": {
      "tweet_id": 2098981759962783908
    }
  }
  ```

---

### B. Conversation Thread Reconstruction: `get_thread`

Reconstructs an entire conversation thread leading up to and following a tweet. You can pass **any** tweet ID within the conversation chain; X discovers the parent thread and context.

- **Arguments**:
  - `tweet_id` (*integer*, required): Any tweet ID belonging to the thread.
  - `limit` (*integer*, optional, default `50`): Maximum tweets to retrieve in the thread.
- **MCP Invocation**:
  ```json
  {
    "name": "get_thread",
    "arguments": {
      "tweet_id": 2098981759962783908,
      "limit": 50
    }
  }
  ```
- **Returns**: JSON array of tweet objects ordered chronologically representing the conversation.

---

### C. Direct Replies: `get_tweet_replies`

Retrieves top-level replies posted directly to a specific tweet.

- **Arguments**:
  - `tweet_id` (*integer*, required): The numeric tweet ID.
  - `limit` (*integer*, optional, default `20`, max `100`): Maximum number of replies.
- **MCP Invocation**:
  ```json
  {
    "name": "get_tweet_replies",
    "arguments": {
      "tweet_id": 2098981759962783908,
      "limit": 20
    }
  }
  ```

---

### D. Advanced Tweet Search: `search`

Searches X for tweets matching complex queries, topics, hashtags, or handles.

- **Arguments**:
  - `query` (*string*, required): Search term with native X query operators.
  - `limit` (*integer*, optional, default `20`, max `100`): Max tweets to return.
  - `mode` (*string*, optional, default `"latest"`): `"latest"` (chronological), `"top"` (relevance/engagement), or `"media"` (photos/videos).
- **Operators Reference**:
  - `from:username` — Tweets from a specific account.
  - `to:username` — Replies sent to a specific account.
  - `@username` — Tweets mentioning a specific account.
  - `"exact match"` — Exact phrase search.
  - `since:YYYY-MM-DD` / `until:YYYY-MM-DD` — Date boundary filters.
  - `filter:media` / `filter:links` / `filter:images` — Media filters.
  - `min_faves:100` / `min_retweets:50` — Engagement thresholds.
  - `lang:en` — Language isolation.
- **MCP Invocation**:
  ```json
  {
    "name": "search",
    "arguments": {
      "query": "from:NASA filter:media min_faves:500",
      "limit": 10,
      "mode": "latest"
    }
  }
  ```

---

### E. Author Timelines: `get_user_tweets` & `get_user_media`

Fetches recent posts or media posts directly from a user's profile.

- **Arguments**:
  - `username` (*string*, required): Account handle **without** `@` (e.g. `"NASA"`).
  - `limit` (*integer*, optional, default `20`, max `100`): Max tweets.
- **MCP Invocation**:
  ```json
  {
    "name": "get_user_tweets",
    "arguments": {
      "username": "NASA",
      "limit": 25
    }
  }
  ```

---

### F. Fact-Checking & Context: `get_community_notes`

Retrieves Community Notes attached to a tweet, providing crowd-sourced context or fact-checks.

- **Arguments**:
  - `tweet_id` (*integer*, required): The numeric tweet ID.
- **MCP Invocation**:
  ```json
  {
    "name": "get_community_notes",
    "arguments": {
      "tweet_id": 2098981759962783908
    }
  }
  ```

---

### G. Governed Write & Interaction Actions ⚠️

> [!WARNING]
> These actions mutate state on X. Always require explicit user intent before invoking write tools. Never invoke as an unprompted side effect of a read query.

| Action | Tool Name | Arguments | Notes |
|---|---|---|---|
| **Post Tweet / Reply / Quote** | `post_tweet` | `text` (*str*), optional `reply_to` (*int*), `quote_tweet` (*int*), `media_ids` (*str*) | Standard 280 char limit (25k for X Premium). Use `reply_to` for in-thread replies, `quote_tweet` to quote. |
| **Delete Tweet** | `delete_tweet` | `tweet_id` (*int*) | Permanently removes an owned tweet. |
| **Like / Unlike** | `like_tweet` / `unlike_tweet` | `tweet_id` (*int*) | Favorites / un-favorites a tweet. |
| **Retweet / Unretweet** | `retweet` / `unretweet` | `tweet_id` (*int*) | Reposts / cancels repost of a tweet. |
| **Bookmark / Unbookmark** | `bookmark_tweet` / `unbookmark_tweet` | `tweet_id` (*int*) | Saves / removes from user bookmarks. |
| **Schedule Tweet** | `schedule_tweet` | `text` (*str*), `execute_at` (*ISO 8601 str*), optional `reply_to` (*int*) | Schedules tweet for future posting. **Gateway Enrichment**: The gateway automatically enriches response with `scheduled_id` recovered from listings. |

---

## 4. Response Schema & Payload Structure

The raw MCP tool response wraps results inside a JSON-RPC envelope:
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "<JSON encoded string>"
      }
    ],
    "isError": false
  }
}
```

Parse `result.content[0].text` as JSON. A typical tweet object contains:

```json
{
  "id": 2098981759962783908,
  "url": "https://x.com/NASA/status/2098981759962783908",
  "text": "Europa Clipper has successfully deployed its solar arrays in space! 🚀🛰️",
  "author_username": "NASA",
  "author_name": "NASA",
  "author_id": 11348282,
  "created_at": "2026-10-14T17:45:00+00:00",
  "reply_count": 842,
  "retweet_count": 3120,
  "like_count": 18450,
  "quote_count": 412,
  "view_count": 650000,
  "lang": "en",
  "media_urls": [
    "https://pbs.twimg.com/media/GZbCdEaW4AA1234.jpg"
  ],
  "hashtags": ["EuropaClipper"],
  "urls": [],
  "user_mentions": [],
  "in_reply_to_tweet_id": null
}
```

### Critical Error Shape Detection

Handle both levels of failure:
1. **Protocol-level error**: `result.isError == true` — The call was rejected (e.g., tool disabled by admin, bad arguments).
2. **Application-level error**: `result.isError == false`, but parsed JSON contains `{"error": "..."}`:
   - Example: `{"error": "Tweet 2098981759962783908 not found"}` (tweet deleted, account suspended, or no active session).

---

## 5. Invocation Playbooks

### Option 1: AI Agent Connected via MCP Stdio Bridge
In environments configured with `mcp-remote` (e.g. Claude Desktop, Cursor, Claude Code):
Simply call `get_tweet(tweet_id=2098981759962783908)` directly through the registered `Kxstrel X MCP` tools.

### Option 2: Python Client (`fastmcp`)
```python
import asyncio
import os
from fastmcp import Client

BASE = os.getenv("KXSTREL_BASE_URL", "https://<your-service>.onrender.com")
TOKEN = os.environ["MCP_ACCESS_TOKEN"]

async def read_tweet(tweet_id: int):
    async with Client(f"{BASE}/mcp", auth=TOKEN) as client:
        response = await client.call_tool("get_tweet", {"tweet_id": tweet_id})
        tweet_data = response.content[0].text
        print(tweet_data)

asyncio.run(read_tweet(2098981759962783908))
```

### Option 3: Command-Line Probe Script (Full Diagnostics)
The repository includes a verification probe with token redaction and full exchange recording:
```bash
MCP_ACCESS_TOKEN="<token>" python scripts/live_mcp_probe.py \
  --base-url "https://<your-service>.onrender.com" \
  --live \
  --tool get_tweet \
  --args-json '{"tweet_id": 2098981759962783908}' \
  --out probe_result.json \
  --debug
```

### Option 4: Raw Streamable HTTP Protocol Sequence
To call the gateway directly via HTTP/cURL, execute the mandatory 3-step sequence:

```bash
BASE="https://<your-service>.onrender.com"
TOKEN="$MCP_ACCESS_TOKEN"

# 1. Initialize session & capture session ID
curl -sS -D /tmp/headers.txt \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -X POST "$BASE/mcp" \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"agent","version":"1.0"}}}'

SID=$(grep -i '^mcp-session-id:' /tmp/headers.txt | tr -d '\r' | awk '{print $2}')

# 2. Complete initialized notification (HTTP 202)
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: $SID" \
  -X POST "$BASE/mcp" \
  --data-binary '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# 3. Call tool
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: $SID" \
  -X POST "$BASE/mcp" \
  --data-binary '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_tweet","arguments":{"tweet_id":2098981759962783908}}}'
```

---

## 6. Agent Best Practices & Decision Runbook

### Operational Decision Logic

Follow these procedural steps when fulfilling tweet requests:

1. **Input Detection & ID Resolution**:
   - If the user provides an X/Twitter URL or status link, apply the deterministic parsing rules to extract the numeric integer `tweet_id`.
   - If the user provides a topic, keyword, or user handle, use `search` (with query operators) or `get_user_tweets`.

2. **Intent-to-Tool Selection**:
   - **Read single post**: Call `get_tweet(tweet_id=<int>)`.
   - **Full conversation or parent thread**: Call `get_thread(tweet_id=<int>, limit=50)`.
   - **User comments / direct replies**: Call `get_tweet_replies(tweet_id=<int>, limit=20)`.
   - **Fact verification / context checks**: Call `get_community_notes(tweet_id=<int>)`.
   - **Interactive actions (like, retweet, bookmark, reply, post, delete)**: Ask for user confirmation before executing state mutations.

3. **Response Verification**:
   - If `result.isError == true`: Identify gateway-level failure (disabled tool, unauthenticated, invalid argument type).
   - If `isError == false` but body is `{"error": "..."}`: Identify application-level failure (deleted tweet, private account, no active X account).
   - If payload contains valid tweet data: Parse the JSON string at `result.content[0].text` and proceed to user presentation.

### Presentation Guidelines for Agents
- **Attribution**: Always present the author's handle (`@username`) and display name.
- **Permanent Link**: Provide a clickable markdown link to `https://x.com/<username>/status/<id>`.
- **Metrics**: When summarizing popularity or reach, summarize `likes`, `retweets`, and `views`.
- **Media**: Explicitly mention if the tweet includes photos, video, or external links, embedding image links when appropriate.
- **Thread Context**: If a user asks about a tweet that is part of a larger thread (`in_reply_to_tweet_id != null`), proactively fetch the conversation using `get_thread`.

---

## 7. Troubleshooting & Error Matrix

| Symptom / Error | Cause | Recommended Action |
|---|---|---|
| `401 Unauthorized` (`WWW-Authenticate: Bearer`) | Missing or invalid `MCP_ACCESS_TOKEN`. | Check that the `Authorization: Bearer <token>` header is sent statically. Do not attempt OAuth registration. |
| `RegistrationRejectedError ... 404` | MCP client tried OAuth Dynamic Client Registration. | Configure the client with static headers (e.g. run `scripts/harden_client_config.ps1`). |
| First request after idle hangs or times out | Cold start on hosting platform (e.g. Render). | Configure client timeout to **≥ 120s**. Use `GET /health` with UptimeRobot to keep the service warm. |
| `HTTP 429 Too Many Requests` | Gateway rate limit reached (`RATE_LIMIT_MCP_PER_MIN`). | Back off and retry after the seconds specified in `Retry-After`. |
| `{"error": "Tweet <id> not found"}` | Tweet was deleted, account is private/suspended, or no account configured. | Check `GET /status` to confirm `x_status == "CONNECTED"`. If connected, the tweet is unavailable on X. |
| `isError` mentioning `"disabled by the administrator"` | Tool flag is toggled off in the Admin Dashboard. | Access the Admin Dashboard (`GET /admin`) and re-enable the tool under **Tools**. |
| `isError` mentioning `"remote gateway mode"` | Tool attempted to access local files or mutate account pool. | Tools like `upload_media` or `remove_account` are hard-blocked for security. Use standard tools. |
| Search returns empty array `[]` while status is `CONNECTED` | Upstream cookie invalidation or rate cap on search endpoint. | Re-import fresh `auth_token` and `ct0` cookies using `python scripts/setup_account.py`. |
| Truncated cookie issue | `ct0` cookie was clipped during export. | Verify `ct0` is exactly **160 characters long**. Re-export from browser DevTools if shorter. |

---

## 8. Related Resources

- [`docs/invocation.md`](file:///d:/Xmcp/docs/invocation.md) — Comprehensive transport details, SSE framing, and protocol specs.
- [`docs/token-rotation.md`](file:///d:/Xmcp/docs/token-rotation.md) — Zero-downtime credential rotation procedures.
- [`scripts/live_mcp_probe.py`](file:///d:/Xmcp/scripts/live_mcp_probe.py) — Live diagnostic probe for testing MCP endpoints.
