"""Advertised-origin hardening (F2).

``WWW-Authenticate: Bearer error="invalid_token", resource_metadata="…"`` is
handed to every unauthenticated MCP client, so the origin inside it decides
where that client goes next. It used to be built from client-controlled
headers with no validation: a hostile ``Host`` pointed clients at an attacker
origin, a list-valued ``X-Forwarded-Host`` let its leftmost (caller-supplied)
element win, and an embedded quote injected an extra auth-param.

The contract now: PUBLIC_BASE_URL is authoritative when set; otherwise only a
syntactically valid host[:port] survives, and the value is dropped — never
cleaned up and reused — when it fails.
"""

from __future__ import annotations

import re

from starlette.requests import Request

from app.config import Settings
from app.security import (_forwarded_host, _safe_host, _safe_origin,
                          external_base_url, resource_metadata_url)

# Exactly one Bearer challenge, two auth-params, path intact. A value that
# broke the quoting (extra param, unterminated string) cannot match this.
_CHALLENGE_RE = re.compile(
    r'^Bearer error="invalid_token", resource_metadata="'
    r'(https?://[A-Za-z0-9.:\[\]\-]+)/\.well-known/oauth-protected-resource/mcp"$'
)

# Host values that must never be echoed: quote/comma breakout, scheme, path,
# whitespace, control characters, userinfo, percent-encoding of the above.
_HOSTILE_HOSTS = [
    'evil.example", error="x',
    'evil.example", resource_metadata="https://evil.example/x',
    "evil.example, real.internal",
    "evil.example/path",
    "http://evil.example",
    "javascript:alert(1)",
    "evil.example foo",
    "evil.example\ttab",
    "evil.example\r\n",
    "evil.example\x00",
    "user@evil.example",
    '"evil.example"',
    "evil.example;param=1",
    "evil.example?x=1",
    "evil.example#frag",
    "evil.example%22",
]


def _request(headers: dict[str, str], scheme: str = "http",
             server: tuple[str, int] = ("10.0.0.5", 8000)) -> Request:
    """A request built straight from an ASGI scope, so hostile header bytes
    reach the app exactly as the audit reproduced them (httpx refuses some of
    these values client-side)."""
    scope = {
        "type": "http", "method": "POST", "path": "/mcp", "raw_path": b"/mcp",
        "query_string": b"", "headers": [(k.lower().encode(), v.encode())
                                         for k, v in headers.items()],
        "scheme": scheme, "server": server, "client": ("203.0.113.7", 5555),
        "http_version": "1.1",
    }
    return Request(scope)


def _challenge(request: Request, settings: Settings | None = None) -> str:
    return f'Bearer error="invalid_token", resource_metadata="{resource_metadata_url(request, settings)}"'


def _public(**kwargs) -> Settings:
    return Settings(**kwargs)


# ── the quoted auth-param cannot be broken out of ────────────────────────

def test_hostile_host_never_reaches_the_challenge():
    for hostile in _HOSTILE_HOSTS:
        header = _challenge(_request({"host": hostile}))
        match = _CHALLENGE_RE.match(header)
        assert match, f"{hostile!r} broke the challenge: {header!r}"
        assert "evil.example" not in match.group(1), header
        for bad in ('"', ",", " ", "\t", "\r", "\n"):
            assert bad not in match.group(1), (hostile, header)


def test_hostile_forwarded_host_never_reaches_the_challenge():
    for hostile in _HOSTILE_HOSTS:
        header = _challenge(_request({"x-forwarded-host": hostile}))
        match = _CHALLENGE_RE.match(header)
        assert match, f"{hostile!r} broke the challenge: {header!r}"
        assert "evil.example" not in match.group(1), header


def test_validator_refuses_anything_that_is_not_host_or_host_port():
    for hostile in _HOSTILE_HOSTS:
        assert _safe_host(hostile) is None, hostile
    assert _safe_host("") is None and _safe_host(None) is None
    assert _safe_host("x" * 300) is None, "absurd length"
    assert _safe_host("host:0") is None and _safe_host("host:99999") is None
    # The shapes that must keep working.
    for good in ("x-mcp.onrender.com", "localhost", "127.0.0.1:8000",
                 "sub.domain-1.example:443", "[2001:db8::1]:8443"):
        assert _safe_host(good) == good


# ── a forwarded list cannot promote its attacker element ─────────────────

def test_forwarded_host_list_does_not_let_the_attacker_element_win():
    # Host is the header the edge routes on, so it wins outright here.
    assert external_base_url(_request({
        "host": "real.internal",
        "x-forwarded-host": "attacker.tld, real.internal",
    })) == "http://real.internal"

    # Without a usable Host the forwarded list resolves to its RIGHTMOST
    # element (the one the trusted hop appended), never the caller's prefix.
    assert _forwarded_host("attacker.tld, real.internal") == "real.internal"
    assert _forwarded_host(" real.internal ") == "real.internal"  # list padding only
    assert _forwarded_host("attacker.tld, ") is None, "a trailing empty hop leaves nothing"
    # A single well-formed value is the edge's own report: accepted (only
    # PUBLIC_BASE_URL can make that decision unconditional).
    assert _forwarded_host("real.internal") == "real.internal"
    assert external_base_url(_request({"x-forwarded-host": "attacker.tld, real.internal"})) \
        == "http://real.internal"


def test_scheme_is_restricted_to_http_and_https():
    request = _request({"host": "real.internal", "x-forwarded-proto": "javascript"})
    assert external_base_url(request) == "http://real.internal"
    assert external_base_url(_request({
        "host": "real.internal", "x-forwarded-proto": "https"})) == "https://real.internal"
    # Rightmost hop wins, like X-Forwarded-For.
    assert external_base_url(_request({
        "host": "real.internal", "x-forwarded-proto": "http, https"})) == "https://real.internal"


# ── PUBLIC_BASE_URL is authoritative ─────────────────────────────────────

def test_public_base_url_beats_hostile_headers():
    settings = _public(PUBLIC_BASE_URL="https://x-mcp.example.com")
    request = _request({"host": 'evil.example", error="x',
                        "x-forwarded-host": "attacker.tld, other.tld",
                        "x-forwarded-proto": "javascript"})
    assert external_base_url(request, settings) == "https://x-mcp.example.com"
    assert resource_metadata_url(request, settings) == (
        "https://x-mcp.example.com/.well-known/oauth-protected-resource/mcp"
    )


def test_public_base_url_is_normalised_and_validated():
    settings = _public(PUBLIC_BASE_URL="https://x-mcp.example.com/")
    assert external_base_url(_request({}), settings) == "https://x-mcp.example.com"
    for bad in ("x-mcp.example.com", "https://x-mcp.example.com/prefix",
                "https://x-mcp.example.com/?q=1", "ftp://x-mcp.example.com",
                'https://evil.example", error="x'):
        assert _safe_origin(bad) is None, bad
        # A malformed setting is ignored, never partially used.
        fallback = external_base_url(_request({"host": "real.internal"}),
                                     _public(PUBLIC_BASE_URL=bad))
        assert fallback == "http://real.internal", (bad, fallback)


# ── degraded inputs still produce a usable challenge ────────────────────

def test_no_host_request_still_yields_a_sane_quoted_value():
    header = _challenge(_request({}, server=("", 0)))
    assert header == (
        'Bearer error="invalid_token", '
        'resource_metadata="http://localhost/.well-known/oauth-protected-resource/mcp"'
    )
    # No Host header, but the server address is known: use it.
    assert external_base_url(_request({})) == "http://10.0.0.5:8000"


def test_mcp_401_header_shape_over_http(client):
    """End-to-end: the challenge a real client receives still parses."""
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                       headers={"Host": '"evil.example", error="x'})
    assert resp.status_code == 401
    header = resp.headers["www-authenticate"]
    match = _CHALLENGE_RE.match(header)
    assert match, header
    assert "evil" not in header


def test_startup_warns_about_an_unusable_public_base_url(tmp_path, monkeypatch):
    """A misconfigured PUBLIC_BASE_URL is ignored, not fatal — but the
    operator must not believe the advertised origin is pinned when it is not."""
    from app import main as main_module

    logged: list[str] = []
    monkeypatch.setattr(main_module.log, "warning", lambda msg, *a: logged.append(msg % a))

    def settings(public_base_url: str) -> Settings:
        return Settings(
            MCP_ACCESS_TOKEN="t" * 48, ADMIN_TOKEN="a" * 48,
            DATABASE_URL=f"sqlite:///{tmp_path}/x.db",
            SPECTRE_DB_PATH=f"{tmp_path}/s.db",
            PUBLIC_BASE_URL=public_base_url,
        )

    main_module.create_app(settings("x-mcp.example.com"))  # no scheme
    assert any("PUBLIC_BASE_URL" in message for message in logged), logged

    logged.clear()
    main_module.create_app(settings("https://x-mcp.example.com"))
    assert logged == [], logged
