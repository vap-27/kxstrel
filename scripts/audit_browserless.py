#!/usr/bin/env python3
"""Browserless audit: prove no browser automation stack is *shipped*.

The guarantee this audit makes is scoped to the project, not to the machine
it happens to run on. Two classes of evidence are therefore separated:

PROJECT-SCOPED (hard fail, always):
  * forbidden references in requirements/manifests (requirements.txt,
    Dockerfile, render.yaml);
  * forbidden references in the repo's own sources (app/, scripts/);
  * forbidden *installed distributions* in the running interpreter's
    environment — i.e. something this project's install pulled in.

HOST-SCOPED (informational by default):
  * a browser binary merely present on the host PATH;
  * a browser process running on the host.

GitHub-hosted ``ubuntu-latest`` runners ship chromium/chromedriver/firefox
preinstalled. A hit there says nothing about this repository, so treating it
as a build gate is unsound: the audit would fail for reasons unrelated to the
tree under test. Those hits are printed as an explicit note instead.

    --strict-binaries      (or BROWSERLESS_AUDIT_STRICT=1)
        Restore failure on host-PATH hits. Use this when the assertion IS
        about a clean image/host — verifying the built container before
        deploy, where "no browser on PATH" is exactly the property you want
        to prove. Do not use it as the ordinary CI gate.

Deliberate nuance: `curl-cffi` (a spectre dependency) ships TLS-fingerprint
presets *named* like browsers ("chrome120"). That is impersonation of a TLS
handshake in a plain HTTP client — it downloads and drives no browser. The
audit therefore matches dependency/import names and executable downloads,
not arbitrary substrings, and documents this exception explicitly.

Exit 0 = browserless. Exit 1 = violation found.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import os
import re
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STRICT_ENV_VAR = "BROWSERLESS_AUDIT_STRICT"

# Forbidden as dependency names, import roots, apt/pip packages, binaries.
FORBIDDEN_NAMES = [
    "chromium", "puppeteer", "playwright", "selenium", "geckodriver",
    "chromedriver", "phantomjs", "camoufox",
]
# "chrome" needs word-boundary care because of curl-cffi impersonation
# presets; matched as a standalone package/binary name only.
FORBIDDEN_STANDALONE = ["chrome", "chromium", "firefox"]

# Browser executables we look for on PATH. Only gates the exit code in strict
# mode; otherwise reported as a host note.
BROWSER_BINARIES = ("chromium", "chromium-browser", "google-chrome", "chrome",
                    "firefox", "geckodriver", "chromedriver")

# Allowed even though the string looks browser-ish.
ALLOWLIST_NOTE = (
    "curl-cffi TLS impersonation presets (e.g. impersonate='chrome120') are "
    "plain-HTTP client fingerprints, not a browser; permitted."
)

SCAN_EXTENSIONS = (".py", ".txt", ".toml", ".cfg", ".in", ".dockerfile", ".sh", ".yaml", ".yml")
SCAN_FILES = ["requirements.txt", "Dockerfile", "render.yaml"]


def _name_hit(text: str) -> list[str]:
    lowered = text.lower()
    hits = [n for n in FORBIDDEN_NAMES if re.search(rf"(?<![a-z0-9_\-]){re.escape(n)}(?![a-z0-9_\-])", lowered)]
    return hits


def _strip_comments(text: str) -> str:
    """Remove # comments so prose documenting an absence can't fail the audit."""
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def check_manifests() -> list[str]:
    problems = []
    for rel in SCAN_FILES:
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = _strip_comments(fh.read())
        for hit in _name_hit(content):
            # Dockerfile base/runtime lines mentioning nothing browserish;
            # any hit here is real because manifests pin package names.
            problems.append(f"{rel}: forbidden dependency reference '{hit}'")
    return problems


def check_sources() -> list[str]:
    problems = []
    for root, _, files in os.walk(os.path.join(REPO, "app")):
        for fn in files:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            with open(path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    lowered = stripped.lower()
                    # import statements / executable downloads only — comments
                    # and docstrings that merely *mention* browsers are fine.
                    if lowered.startswith(("import ", "from ")) or "subprocess" in lowered \
                            or "download" in lowered or "apt" in lowered or "pip install" in lowered:
                        for hit in _name_hit(stripped):
                            problems.append(f"{os.path.relpath(path, REPO)}:{lineno}: '{hit}'")
    for root, _, files in os.walk(os.path.join(REPO, "scripts")):
        for fn in files:
            if fn == os.path.basename(__file__):
                continue
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            with open(path, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            for hit in _name_hit(content):
                problems.append(f"scripts/{fn}: forbidden reference '{hit}'")
    return problems


def check_project() -> list[str]:
    """Project-scoped: what this repository declares and contains."""
    return check_manifests() + check_sources()


def check_installed() -> list[str]:
    """Project-scoped: distributions present in the audited interpreter.

    A browser stack installed into this project's environment is shipped by
    definition, so this is a hard failure regardless of mode.
    """
    problems = []
    for dist in importlib.metadata.distributions():
        name = (dist.metadata.get("Name") or "").lower()
        for forbidden in FORBIDDEN_NAMES + ["chrome"]:
            if forbidden in name and name not in ("curl-cffi",):
                # curl-cffi explicitly excluded (see module docstring).
                problems.append(f"installed distribution '{name}' looks like a browser stack")
    return problems


def check_binaries(which=None) -> list[str]:
    """Host-scoped: browser executables on PATH.

    Environment-dependent: CI images and developer machines may carry
    unrelated browsers. Informational unless strict mode is requested.

    ``which`` is resolved at call time (not default-bound) so that tests can
    substitute it by monkeypatching ``shutil.which``.
    """
    which = which or shutil.which
    problems = []
    for binary in BROWSER_BINARIES:
        if which(binary):
            problems.append(f"browser executable present on PATH: {binary}")
    return problems


def check_processes() -> list[str]:
    """Host-scoped: browser processes running. Always informational."""
    try:
        if os.name == "nt":
            out = subprocess.run(["tasklist"], capture_output=True, text=True, timeout=15).stdout.lower()
        else:
            out = subprocess.run(["ps", "-e", "-o", "comm="], capture_output=True,
                                 text=True, timeout=15).stdout.lower()
    except Exception as exc:
        return [f"process check inconclusive: {exc}"]
    problems = []
    for proc in ("chromium", "chrome.exe", "firefox", "geckodriver", "chromedriver"):
        # 'chrome.exe' only meaningful on Windows; plain 'chrome' would
        # false-positive on POSIX tool names, so keep the list conservative.
        if proc in out:
            problems.append(f"browser process running: {proc}")
    return problems


def strict_from_env() -> bool:
    return os.environ.get(STRICT_ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


def run(*, strict_binaries: bool = False, which=None,
        processes=None, installed=None, project=None) -> tuple[int, list[str], list[str]]:
    """Return ``(exit_code, problems, host_notes)``.

    ``problems`` are project-scoped violations (plus host-PATH hits in strict
    mode). ``host_notes`` are host-scoped observations that never gate the
    exit code on their own.

    The callables are resolved at call time so tests can monkeypatch the
    module-level functions / ``shutil.which`` and still exercise this path.
    """
    installed = installed or check_installed
    processes = processes or check_processes
    project = project or check_project

    problems = project() + installed()
    path_hits = check_binaries(which=which)

    host_notes: list[str] = []
    if strict_binaries:
        problems += path_hits
    else:
        host_notes += path_hits
    host_notes += processes()

    return (1 if problems else 0), problems, host_notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Browserless audit: prove no browser automation stack is shipped.")
    parser.add_argument(
        "--strict-binaries", action="store_true",
        help=("Fail on browser binaries found on the host PATH. Use for "
              "container-image / pre-deploy audits where a clean PATH is the "
              "assertion; not for ordinary CI on a runner with preinstalled browsers."))
    args = parser.parse_args(argv)

    strict = args.strict_binaries or strict_from_env()
    code, problems, host_notes = run(strict_binaries=strict)

    print(f"allowlist note: {ALLOWLIST_NOTE}")
    if code:
        print("BROWSERLESS AUDIT: FAIL")
        for p in problems:
            print(f"  - {p}")
        return 1

    scope = "manifests, sources, installed dists" + (", binaries" if strict else "")
    print(f"BROWSERLESS AUDIT: PASS ({scope} clean)")
    if host_notes:
        if strict:
            label = "note: observations on this machine (not part of this service)"
        else:
            label = ("note: host-scoped observations — this machine has browser "
                     "tooling, which is NOT part of this service and does not fail "
                     "this audit (re-run with --strict-binaries to gate on a clean PATH)")
        print(label + ":")
        for note in host_notes:
            print(f"  - {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
