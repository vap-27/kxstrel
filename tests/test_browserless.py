"""Browserless audit semantics.

The audit must separate project-scoped evidence (what this repository
declares, contains, or installs — correct to fail a build) from host-scoped
evidence (a browser merely present on the machine — environment-dependent and
unsound as a build gate). GitHub's ubuntu-latest images ship Chromium and
Firefox preinstalled, so a host-PATH hit there says nothing about this tree.

Nothing in this module depends on the real host: ``shutil.which``, the
process scan and the installed-distribution scan are all substituted.
"""

import importlib.util
import os
import subprocess
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_audit():
    path = os.path.join(REPO, "scripts", "audit_browserless.py")
    spec = importlib.util.spec_from_file_location("audit_browserless", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def audit():
    return _load_audit()


@pytest.fixture()
def no_browser_processes(monkeypatch, audit):
    """Keep the host process scan out of the picture."""
    monkeypatch.setattr(audit, "check_processes", lambda: [])


@pytest.fixture()
def clean_installed(monkeypatch, audit):
    """Pretend the audited environment has no browser-ish distribution."""
    monkeypatch.setattr(audit, "check_installed", lambda: [])


def _fake_which(*found):
    """Return a ``shutil.which`` stand-in that resolves only ``found``."""
    table = set(found)
    return lambda name: f"/usr/bin/{name}" if name in table else None


# ── 1. host-PATH hits are not a build gate ───────────────────────────────


def test_audit_passes_with_unrelated_browser_binaries_on_path(
        audit, monkeypatch, no_browser_processes, capsys):
    """A browser on the host PATH must not fail the default audit."""
    monkeypatch.setattr(audit.shutil, "which", _fake_which("chromium", "firefox", "chromedriver"))
    assert audit.main([]) == 0
    out = capsys.readouterr().out
    assert "BROWSERLESS AUDIT: PASS" in out
    # ... but the hit is still reported, clearly labelled as host-scoped.
    assert "browser executable present on PATH: chromium" in out
    assert "NOT part of this service" in out


def test_host_path_hits_are_reported_as_notes_not_problems(audit, monkeypatch):
    monkeypatch.setattr(audit.shutil, "which", _fake_which("google-chrome"))
    code, problems, host_notes = audit.run(processes=lambda: [])
    assert code == 0
    assert problems == []
    assert any("google-chrome" in n for n in host_notes)


def test_host_relative_process_hits_stay_informational(audit, monkeypatch):
    monkeypatch.setattr(audit.shutil, "which", _fake_which())
    code, problems, host_notes = audit.run(
        processes=lambda: ["browser process running: chrome.exe"],
        installed=lambda: [])
    assert (code, problems) == (0, [])
    assert "browser process running: chrome.exe" in host_notes


def test_audit_passes_on_a_clean_host_without_notes(
        audit, monkeypatch, no_browser_processes, clean_installed, capsys):
    monkeypatch.setattr(audit.shutil, "which", _fake_which())
    assert audit.main([]) == 0
    assert "BROWSERLESS AUDIT: PASS" in capsys.readouterr().out


# ── 2. project-declared browser stacks still fail ────────────────────────


def test_audit_fails_when_project_declares_browser_dependency(audit, monkeypatch, tmp_path):
    """A forbidden name in requirements.txt is a real, project-scoped failure."""
    (tmp_path / "requirements.txt").write_text("fastapi\nplaywright>=1.40\n")
    (tmp_path / "app").mkdir()
    (tmp_path / "scripts").mkdir()
    monkeypatch.setattr(audit, "REPO", str(tmp_path))
    monkeypatch.setattr(audit.shutil, "which", _fake_which("chromium"))

    code, problems, _ = audit.run(processes=lambda: [], installed=lambda: [])
    assert code == 1
    assert any("requirements.txt" in p and "playwright" in p for p in problems)


def test_audit_fails_when_manifest_hit_reported_by_scanner(audit, monkeypatch):
    """``check_project()`` itself must surface the violation, not just main()."""
    monkeypatch.setattr(audit, "check_manifests", lambda: ["requirements.txt: 'selenium'"])
    assert audit.check_project() == ["requirements.txt: 'selenium'"]
    monkeypatch.setattr(audit.shutil, "which", _fake_which())
    assert audit.run(processes=lambda: [], installed=lambda: [])[0] == 1


def test_audit_fails_on_browser_reference_in_sources(audit, monkeypatch, tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "driver.py").write_text("import selenium.webdriver\n")
    (tmp_path / "scripts").mkdir()
    monkeypatch.setattr(audit, "REPO", str(tmp_path))
    problems = audit.check_sources()
    assert any("selenium" in p for p in problems), problems


def test_audit_main_exits_nonzero_on_project_violation(
        audit, monkeypatch, no_browser_processes, capsys):
    monkeypatch.setattr(audit, "check_project", lambda: ["requirements.txt: 'puppeteer'"])
    assert audit.main([]) == 1
    assert "BROWSERLESS AUDIT: FAIL" in capsys.readouterr().out


def test_script_exit_code_contract_on_real_tree():
    """The shipped tree passes, and the process really exits 0."""
    proc = subprocess.run([sys.executable, os.path.join(REPO, "scripts", "audit_browserless.py")],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ── 3. installed distributions are project-scoped failures ───────────────


class _FakeDist:
    def __init__(self, name: str):
        self.metadata = {"Name": name}


def test_no_browser_distribution_installed(audit):
    """The real environment running this suite must be browser-stack free."""
    assert audit.check_installed() == []


def test_audit_fails_when_forbidden_distribution_is_installed(audit, monkeypatch):
    monkeypatch.setattr(audit.importlib.metadata, "distributions",
                        lambda: [_FakeDist("puppeteer-core"), _FakeDist("fastapi")])
    problems = audit.check_installed()
    assert problems == ["installed distribution 'puppeteer-core' looks like a browser stack"]

    monkeypatch.setattr(audit.shutil, "which", _fake_which())
    code, problems, _ = audit.run(processes=lambda: [])
    assert code == 1
    assert any("puppeteer-core" in p for p in problems)


def test_curl_cffi_tls_presets_are_allowlisted(audit, monkeypatch):
    """spectre depends on curl-cffi, whose TLS presets are named like browsers."""
    monkeypatch.setattr(audit.importlib.metadata, "distributions", lambda: [_FakeDist("curl-cffi")])
    assert audit.check_installed() == []


def test_installed_check_is_hard_failure_even_in_default_mode(audit, monkeypatch):
    monkeypatch.setattr(audit.shutil, "which", _fake_which())
    code, problems, _ = audit.run(processes=lambda: [],
                                  installed=lambda: ["installed distribution 'selenium' is present"])
    assert code == 1
    assert problems == ["installed distribution 'selenium' is present"]


# ── 4. strict mode ───────────────────────────────────────────────────────


def test_strict_mode_fails_on_host_path_hit_and_default_does_not(audit, monkeypatch):
    monkeypatch.setattr(audit.shutil, "which", _fake_which("chromium", "chromedriver"))

    default_code, default_problems, default_notes = audit.run(processes=lambda: [], installed=lambda: [])
    assert default_code == 0
    assert default_problems == []
    assert any("chromium" in n for n in default_notes)

    strict_code, strict_problems, strict_notes = audit.run(
        strict_binaries=True, processes=lambda: [], installed=lambda: [])
    assert strict_code == 1
    assert "browser executable present on PATH: chromium" in strict_problems
    assert "browser executable present on PATH: chromedriver" in strict_problems
    # Host notes are no longer duplicated once they are problems.
    assert strict_notes == []


def test_strict_mode_passes_on_a_clean_path(audit, monkeypatch):
    monkeypatch.setattr(audit.shutil, "which", _fake_which())
    code, problems, _ = audit.run(strict_binaries=True, processes=lambda: [], installed=lambda: [])
    assert (code, problems) == (0, [])


def test_strict_flag_and_env_var_both_gate_exit_code(audit, monkeypatch, capsys):
    monkeypatch.setattr(audit.shutil, "which", _fake_which("firefox"))
    monkeypatch.delenv(audit.STRICT_ENV_VAR, raising=False)

    assert audit.main([]) == 0
    assert audit.main(["--strict-binaries"]) == 1

    monkeypatch.setenv(audit.STRICT_ENV_VAR, "1")
    assert audit.main([]) == 1
    out = capsys.readouterr().out
    assert "BROWSERLESS AUDIT: FAIL" in out
    assert "browser executable present on PATH: firefox" in out

    monkeypatch.setenv(audit.STRICT_ENV_VAR, "0")
    assert audit.main([]) == 0


def test_strict_env_var_parsing(audit, monkeypatch):
    for value, expected in (("1", True), ("true", True), ("YES", True), ("on", True),
                            ("0", False), ("", False), ("off", False)):
        monkeypatch.setenv(audit.STRICT_ENV_VAR, value)
        assert audit.strict_from_env() is expected, value


# ── 5. guarantees kept from before ───────────────────────────────────────


def test_no_browser_strings_in_requirements():
    raw = open(os.path.join(REPO, "requirements.txt")).read()
    # Strip comments: documenting the absence of a browser must not fail.
    req = "\n".join(line.split("#", 1)[0] for line in raw.splitlines()).lower()
    for forbidden in ("chromium", "puppeteer", "playwright", "selenium"):
        assert forbidden not in req, forbidden


def test_audit_still_scans_the_real_manifests(audit):
    """The scanner must actually find a planted violation in a real file."""
    assert audit.check_project() == []


def test_path_hits_do_not_shadow_project_scope_reporting(audit, monkeypatch, capsys):
    """A host-path hit must never mask (or replace) a project violation."""
    monkeypatch.setattr(audit, "check_project",
                        lambda: ["Dockerfile: forbidden dependency reference 'selenium'"])
    monkeypatch.setattr(audit.shutil, "which", _fake_which("chromium"))
    monkeypatch.setattr(audit, "check_processes", lambda: [])
    assert audit.main([]) == 1
    assert "Dockerfile" in capsys.readouterr().out


def test_module_docstring_documents_scope_split(audit):
    doc = audit.__doc__ or ""
    for token in ("PROJECT-SCOPED", "HOST-SCOPED", "strict-binaries", "Exit 0"):
        assert token in doc, token


def test_which_is_resolved_at_call_time(audit, monkeypatch):
    """Guards the monkeypatch seam used by these tests."""
    monkeypatch.setattr(audit.shutil, "which", _fake_which())
    before = audit.check_binaries()
    monkeypatch.setattr(audit.shutil, "which", _fake_which("firefox"))
    after = audit.check_binaries()
    assert before == [] and after == ["browser executable present on PATH: firefox"]
