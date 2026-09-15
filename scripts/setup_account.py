#!/usr/bin/env python3
"""One-time credential setup client + encryption key generator.

- Prompts for (never echoes) the X session cookies and POSTs them to the
  running gateway's /admin/account endpoint, which encrypts + persists them.
- No browser automation: you copy the cookies manually from your own logged-in
  browser session (see README), exactly like `spectre add` does locally.

Usage:
    python scripts/setup_account.py --generate-key
    python scripts/setup_account.py --base-url https://x-mcp.onrender.com --label myaccount
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

import httpx


def generate_key() -> int:
    from cryptography.fernet import Fernet
    print(Fernet.generate_key().decode())
    return 0


def setup(base_url: str, label: str, admin_token: str) -> int:
    if base_url.startswith("http://") and "localhost" not in base_url and "127.0.0.1" not in base_url:
        print("error: refusing to send credentials over plain http to a non-local URL",
              file=sys.stderr)
        return 2
    auth_token = getpass.getpass("auth_token (hidden input): ").strip()
    ct0 = getpass.getpass("ct0 (hidden input): ").strip()
    if not auth_token or not ct0:
        print("error: both auth_token and ct0 are required", file=sys.stderr)
        return 2
    if len(ct0) != 160:
        print(f"warning: ct0 is {len(ct0)} chars; the full value is usually 160 — "
              "partial cookies fail silently. Continuing anyway.")
    url = base_url.rstrip("/") + "/admin/account"
    try:
        resp = httpx.post(url, json={"label": label, "auth_token": auth_token,
                                     "ct0": ct0, "enabled": True},
                          headers={"Authorization": f"Bearer {admin_token}"}, timeout=90)
    except Exception as exc:
        print(f"error: request failed: {exc}", file=sys.stderr)
        return 1
    if resp.status_code >= 400:
        print(f"error: {resp.status_code} (see server logs; response body not echoed "
              "to avoid leaking anything)", file=sys.stderr)
        return 1
    data = resp.json()
    print(f"saved label={data.get('label')} x_status={data.get('x_status')}")
    for warning in data.get("warnings", []):
        print(f"warning: {warning}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Kxstrel X MCP credential setup")
    parser.add_argument("--generate-key", action="store_true")
    parser.add_argument("--base-url", default=os.environ.get("KXSTREL_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--label", default=os.environ.get("KXSTREL_LABEL", "myaccount"))
    parser.add_argument("--admin-token", default=os.environ.get("ADMIN_TOKEN", ""))
    args = parser.parse_args()
    if args.generate_key:
        return generate_key()
    if not args.admin_token:
        print("error: provide --admin-token or set ADMIN_TOKEN", file=sys.stderr)
        return 2
    return setup(args.base_url, args.label, args.admin_token)


if __name__ == "__main__":
    sys.exit(main())
