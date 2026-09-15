# MCP connection examples

Base URL examples: local `http://localhost:8000`, Render
`https://x-mcp.onrender.com`. All `/mcp` calls need
`Authorization: Bearer $MCP_ACCESS_TOKEN`.

## 1. Raw Streamable HTTP (curl)

```bash
BASE=https://x-mcp.onrender.com
AUTH="Authorization: Bearer $MCP_ACCESS_TOKEN"
ACC="Accept: application/json, text/event-stream"

# initialize -> capture session id
SID=$(curl -sS -D - -X POST $BASE/mcp -H "$AUTH" -H "$ACC" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
       "params":{"protocolVersion":"2025-06-18","capabilities":{},
                 "clientInfo":{"name":"curl-demo","version":"1.0"}}}' \
  | grep -i '^mcp-session-id:' | tr -d '\r' | awk '{print $2}')
echo "session: $SID"

# handshake notification
curl -sS -X POST $BASE/mcp -H "$AUTH" -H "$ACC" \
  -H 'Content-Type: application/json' -H "mcp-session-id: $SID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# list tools (the live installed set — count, don't assume)
curl -sS -X POST $BASE/mcp -H "$AUTH" -H "$ACC" \
  -H 'Content-Type: application/json' -H "mcp-session-id: $SID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

# read-only call: user search
curl -sS -X POST $BASE/mcp -H "$AUTH" -H "$ACC" \
  -H 'Content-Type: application/json' -H "mcp-session-id: $SID" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
       "params":{"name":"search_users","arguments":{"query":"nasa","limit":1}}}'

# read-only call: profile lookup
curl -sS -X POST $BASE/mcp -H "$AUTH" -H "$ACC" \
  -H 'Content-Type: application/json' -H "mcp-session-id: $SID" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call",
       "params":{"name":"get_user","arguments":{"username":"nasa"}}}'
```

## 2. Python (FastMCP client)

```python
import asyncio
from fastmcp import Client

BASE = "https://x-mcp.onrender.com/mcp"
TOKEN = "MCP_ACCESS_TOKEN"  # noqa: S105 - placeholder, use env in real code

async def main():
    async with Client(BASE, auth=TOKEN) as client:
        tools = await client.list_tools()
        print("tool count:", len(tools))
        print(await client.call_tool("search", {"query": "from:nasa", "limit": 3}))
        print(await client.call_tool("get_user", {"username": "nasa"}))
        # Write ops are explicit calls, e.g.:
        # print(await client.call_tool("post_tweet", {"text": "hello"}))

asyncio.run(main())
```

## 3. Claude Code / Desktop / Cursor (stdio-only clients)

Use `mcp-remote` as a bridge to the remote Streamable HTTP endpoint:

```json
{
  "mcpServers": {
    "kxstrel-x-mcp": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote",
        "https://x-mcp.onrender.com/mcp",
        "--header", "Authorization: Bearer ${MCP_ACCESS_TOKEN}"
      ],
      "env": { "MCP_ACCESS_TOKEN": "paste-token-here" }
    }
  }
}
```

## 4. Health / status / diagnostics

```bash
curl $BASE/health            # UptimeRobot target: {"status":"ok",...}
curl $BASE/status            # x_status, tool_count, versions — no secrets
curl -H "$AUTH" $BASE/tools  # live tool list + read/destructive flags
```

## 5. Deployment-test checklist mapping (spec §"Deployment test")

| Step | How |
|---|---|
| 1–3 start, no browser, `/health` | `pip install -r requirements.txt && python -m app.main`; `curl /health`; `audit_browserless.py` |
| 4 DB connectivity | `/diagnostics` → `database.ok: true`; startup logs `database backend=...` |
| 5–7 insert creds, start spectre, validate | `POST /admin/account` → `x_status: CONNECTED` |
| 8–10 MCP connect, search, profile | sections 1–2 above |
| 11 one write (only if valid) | `tools/call post_tweet` with a throwaway test post, then `delete_tweet` |
| 12–14 no browser, no secrets | `audit_browserless.py`; `smoke_test.py` leak checks; inspect logs |
| 15–16 restart, persistence | restart process, `GET /status` still `CONNECTED` without re-setup |
| 17–21 Render deploy, `$PORT`, remote MCP, sleep recovery | Render dashboard deploy → `/health` → remote handshake → let free instance sleep → wake → `/status` `CONNECTED` |

`scripts/smoke_test.py` automates rows 1–10 + 12–14 (add `--live` for a
single read-only X call).
