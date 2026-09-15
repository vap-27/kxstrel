"""B12/B13: secret-strength startup validation and registry memory bounds."""

from __future__ import annotations

import asyncio
import os

import pytest

from app.client_registry import MAX_VERSIONS_PER_CLIENT, ClientStats, ClientRegistryMiddleware
from app.config import MIN_SECRET_LENGTH, Settings, secret_strength_problems
from app.crypto import CredentialCrypto, generate_key


# ── B12: weak secrets are refused at startup ─────────────────────────────

def test_weak_bearer_token_is_reported():
    settings = Settings(MCP_ACCESS_TOKEN="short", ADMIN_TOKEN="", CREDENTIAL_ENCRYPTION_KEY="")
    problems = secret_strength_problems(settings)
    assert len(problems) == 1
    assert "MCP_ACCESS_TOKEN" in problems[0]
    assert str(MIN_SECRET_LENGTH) in problems[0]
    assert "secrets.token_urlsafe" in problems[0]


def test_weak_admin_token_and_key_are_reported():
    settings = Settings(MCP_ACCESS_TOKEN="x" * 48, ADMIN_TOKEN="weak",
                        CREDENTIAL_ENCRYPTION_KEY="tiny")
    names = " ".join(secret_strength_problems(settings))
    assert "ADMIN_TOKEN" in names and "CREDENTIAL_ENCRYPTION_KEY" in names


def test_unset_secrets_are_not_a_strength_problem():
    """Empty means 'not configured': the auth layer answers 503, startup is fine."""
    assert secret_strength_problems(Settings(MCP_ACCESS_TOKEN="", ADMIN_TOKEN="",
                                             CREDENTIAL_ENCRYPTION_KEY="")) == []


def test_exactly_minimum_length_passes():
    assert secret_strength_problems(Settings(MCP_ACCESS_TOKEN="y" * MIN_SECRET_LENGTH)) == []


def test_configured_test_fixtures_pass_validation():
    """The conftest tokens must satisfy the floor (they are 48 chars)."""
    problems = secret_strength_problems(Settings(
        MCP_ACCESS_TOKEN=os.environ["MCP_ACCESS_TOKEN"],
        ADMIN_TOKEN=os.environ["ADMIN_TOKEN"],
        CREDENTIAL_ENCRYPTION_KEY=os.environ["CREDENTIAL_ENCRYPTION_KEY"],
    ))
    assert problems == []


def test_debug_does_not_relax_the_secret_floor():
    """Documented decision: DEBUG=true must not admit a weak token."""
    settings = Settings(DEBUG=True, MCP_ACCESS_TOKEN="short", ADMIN_TOKEN="short")
    assert len(secret_strength_problems(settings)) == 2


def test_create_app_refuses_weak_secrets(tmp_path):
    from app.main import create_app

    with pytest.raises(RuntimeError, match="MCP_ACCESS_TOKEN"):
        create_app(Settings(
            MCP_ACCESS_TOKEN="weak",
            ADMIN_TOKEN="a" * 48,
            DATABASE_URL=f"sqlite:///{tmp_path}/x.db",
            SPECTRE_DB_PATH=f"{tmp_path}/s.db",
        ))


# ── B13: bounded per-client version tracking ─────────────────────────────

class _Info:
    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version


class _Message:
    def __init__(self, name: str, version: str):
        self.params = type("P", (), {"client_info": _Info(name, version)})()


class _Context:
    def __init__(self, name: str, version: str):
        self.message = _Message(name, version)


async def _call_next(context):  # pragma: no cover - passthrough
    return None


def test_client_stats_version_cap_counts_overflow():
    stats = ClientStats(name="flood")
    for i in range(MAX_VERSIONS_PER_CLIENT + 5):
        stats.record_version(f"v{i}")
    assert len(stats.versions) == MAX_VERSIONS_PER_CLIENT
    assert stats.version_overflow == 5
    # A repeat of a tracked version still counts as usage, not overflow.
    stats.record_version("v0")
    assert stats.versions["v0"] == 2
    assert stats.version_overflow == 5


def test_registry_caps_versions_from_wire_clientinfo():
    async def go():
        registry = ClientRegistryMiddleware()
        for i in range(MAX_VERSIONS_PER_CLIENT * 3):
            await registry.on_initialize(_Context("flood", f"v{i}"), _call_next)
        snapshot = registry.snapshot()
        entry = next(c for c in snapshot if c["name"] == "flood")
        assert len(entry["versions"]) == MAX_VERSIONS_PER_CLIENT
        assert entry["version_overflow"] == MAX_VERSIONS_PER_CLIENT * 3 - MAX_VERSIONS_PER_CLIENT
        assert entry["handshakes"] == MAX_VERSIONS_PER_CLIENT * 3

    asyncio.run(go())


def test_registry_caps_distinct_client_names():
    from app.client_registry import MAX_CLIENTS

    async def go():
        registry = ClientRegistryMiddleware()
        for i in range(MAX_CLIENTS + 20):
            await registry.on_initialize(_Context(f"client-{i}", "1"), _call_next)
        assert registry.client_count() == MAX_CLIENTS

    asyncio.run(go())


# ── credential encryption at rest (the other half of secret handling) ────

def test_roundtrip():
    crypto = CredentialCrypto(generate_key())
    token = crypto.encrypt("auth_token_secret_value")
    assert token != "auth_token_secret_value"
    assert crypto.decrypt(token) == "auth_token_secret_value"


def test_wrong_key_fails():
    crypto = CredentialCrypto(generate_key())
    token = crypto.encrypt("x")
    with pytest.raises(ValueError):
        CredentialCrypto(generate_key()).decrypt(token)


def test_missing_key_rejected():
    with pytest.raises(ValueError):
        CredentialCrypto("")


def test_garbage_key_rejected():
    with pytest.raises(ValueError):
        CredentialCrypto("not-a-valid-fernet-key")
