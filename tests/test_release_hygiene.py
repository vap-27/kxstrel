"""Release hygiene: the version, the changelog and the deploy blueprint.

Two failure modes an operator hits, not a test: shipping a version the
changelog does not describe, and a blueprint that silently hardcodes a value
the operator believes they set in the dashboard. Both are pinned here against
the files themselves.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from app import __version__

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
RENDER = ROOT / "render.yaml"

# Every environment variable the blueprint declares must be entered by the
# operator (sync: false). Two of them are not secrets but still deployment
# decisions: LOG_LEVEL and SESSION_CHECK_INTERVAL_SECONDS used to carry
# `value:` defaults, which silently overrode whatever the operator set in the
# Render dashboard.
OPERATOR_ENTERED_KEYS = (
    "ADMIN_TOKEN",
    "BACKUP_DATABASE_URL",
    "CREDENTIAL_ENCRYPTION_KEY",
    "DATABASE_URL",
    "LOG_LEVEL",
    "MCP_ACCESS_TOKEN",
    "PUBLIC_BASE_URL",
    "REDIS_URL",
    "SESSION_CHECK_INTERVAL_SECONDS",
)

_VERSION_HEADING = re.compile(r"^##\s*\[(\d+\.\d+\.\d+)\]", re.MULTILINE)


def _changelog_versions() -> list[tuple[int, ...]]:
    text = CHANGELOG.read_text(encoding="utf-8")
    return [tuple(int(p) for p in m.group(1).split("."))
            for m in _VERSION_HEADING.finditer(text)]


def test_app_version_matches_the_newest_changelog_heading():
    """app.__version__ and the newest CHANGELOG heading cannot drift apart:
    a release that bumps one and not the other fails here."""
    versions = _changelog_versions()
    assert versions, "CHANGELOG.md has no '## [x.y.z]' release headings"

    newest = max(versions)
    assert ".".join(str(p) for p in newest) == __version__, (
        f"CHANGELOG's newest release is {newest}, app.__version__ is {__version__}"
    )
    # Keep a Changelog reads newest-first, and the baseline stays documented.
    assert versions == sorted(versions, reverse=True), "changelog is not newest-first"
    assert (1, 0, 0) in versions, "the v1.0.0 baseline entry went missing"


def test_render_blueprint_requires_operator_entered_values():
    doc = yaml.safe_load(RENDER.read_text(encoding="utf-8"))
    env_vars = doc["services"][0]["envVars"]
    declared = [entry["key"] for entry in env_vars]
    assert sorted(declared) == sorted(OPERATOR_ENTERED_KEYS), (
        f"blueprint keys changed: {sorted(declared)}"
    )
    for entry in env_vars:
        key = entry["key"]
        assert entry.get("sync") is False, f"{key} must be sync: false (operator-entered)"
        assert "value" not in entry, f"{key} must not ship a hardcoded value"
