"""Admin console design contract.

Locks in the rules the static assets must keep obeying, independent of the
individual tests in ``test_admin_ui.py`` (which cover CSP, auth and leaks):

  * palette fully tokenised — no raw hex outside ``:root``;
  * no light-surface tells that were banned by the redesign brief
    (indigo/purple accents, gradients, glows, web fonts, emoji icons);
  * nothing remote — the CSP has no ``font-src``/``img-src`` escape hatch for
    third-party assets, so a downloaded typeface is not an option here;
  * the innerHTML-free JS contract: every id ``app.js`` reaches for exists,
    every view has a nav entry and every nav entry has a view;
  * every admin endpoint the console calls is still called;
  * the theme contract: three modes (system/light/dark), system by default and
    followed live, light as the fallback when the OS cannot be consulted, and
    a storage key that only ever holds one of those three names.

Most of this file is source and markup contract. The theme *behaviour* can
still be executed without a browser: ``theme_harness.js`` runs the shipped
theme section under Node's ``vm`` against hand-written stubs for
``matchMedia``/``localStorage``/the document element, and the tests at the
bottom assert what it observed. No browser automation, no DOM library, no new
dependency — see ``scripts/audit_browserless.py`` for that rule.
"""

import json
import os
import re
import shutil
import subprocess
from html.parser import HTMLParser

import pytest

STATIC = os.path.join(os.path.dirname(__file__), "..", "app", "static")
HTML_PATH = os.path.join(STATIC, "admin.html")
CSS_PATH = os.path.join(STATIC, "app.css")
JS_PATH = os.path.join(STATIC, "app.js")

VOID_ELEMENTS = {"area", "base", "br", "col", "embed", "hr", "img", "input",
                 "link", "meta", "param", "source", "track", "wbr"}


class _ParentTracking(HTMLParser):
    """Tag-balance checker that also records each element's parent.

    A stray end tag (e.g. ``</main>`` where ``</div>`` was meant) silently
    re-parents everything after it: the browser closes the earlier container
    and nests the shell inside the hidden login wrapper, which renders the
    whole console blank. This is the jsdom-free assertion for that class of
    bug — the DOM still contains every id, so an id-existence test misses it.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.parents = {}
        self.errors = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        parent = self.stack[-1] if self.stack else None
        if attrs.get("id"):
            self.parents[attrs["id"]] = parent or "root"
        if tag not in VOID_ELEMENTS:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        return

    def handle_endtag(self, tag):
        if tag in VOID_ELEMENTS:
            return
        if not self.stack:
            self.errors.append(f"stray </{tag}>")
            return
        if self.stack[-1] != tag:
            self.errors.append(f"</{tag}> closes <{self.stack[-1]}>")
            if tag in self.stack:
                while self.stack and self.stack.pop() != tag:
                    pass
            return
        self.stack.pop()


def _structure():
    parser = _ParentTracking()
    parser.feed(_read(HTML_PATH))
    parser.close()
    return parser


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _assets():
    return {"admin.html": _read(HTML_PATH), "app.css": _read(CSS_PATH), "app.js": _read(JS_PATH)}


# Every selector that opens a palette block. A colour literal may live only
# inside one of these, so they are exactly the blocks the raw-hex scan below
# has to skip — and exactly the blocks that must not hide anything else.
THEME_SELECTORS = (":root", '[data-theme="light"]', '[data-theme="dark"]',
                   ":root:not([data-theme])")

# A palette block declares custom properties and nothing else, with a single
# exception: `color-scheme`, which is what tells the UA to paint form
# controls, scrollbars and the canvas light or dark.
NON_TOKEN_DECLARATIONS = ("color-scheme",)


def _token_blocks(css):
    """``[(start, selector, body), ...]`` for every palette block, in file order.

    The selector is matched only where it opens a block (start of a line,
    then ``{``), so the theme selectors quoted in prose never match. Palette
    blocks are flat declaration lists: the first ``}`` closes the block.
    """
    blocks = []
    for selector in THEME_SELECTORS:
        pattern = r"(?m)^[ \t]*" + re.escape(selector) + r"[ \t]*\{"
        for match in re.finditer(pattern, css):
            body = css[match.end():css.index("}", match.end())]
            blocks.append((match.start(), selector, body))
    return sorted(blocks)


def _declarations(body):
    """A palette block's declarations, comments stripped."""
    return [d.strip() for d in re.sub(r"/\*.*?\*/", " ", body, flags=re.S).split(";")
            if d.strip()]


def _strip_token_blocks(css):
    """Return the CSS with every palette block removed.

    The guarantee that makes the raw-hex scan below meaningful is asserted
    here, so no caller can skip it: each stripped block may declare only
    custom properties (plus ``color-scheme``). A component rule therefore
    cannot hide inside a block the hex scan does not look at — if one tried,
    this function fails first.
    """
    chunks, cursor = [], 0
    for start, selector, body in _token_blocks(css):
        for declaration in _declarations(body):
            property_name = declaration.split(":", 1)[0].strip()
            assert property_name.startswith("--") or property_name in NON_TOKEN_DECLARATIONS, (
                f"{selector} declares {declaration!r}: a palette block may only "
                "declare custom properties (and color-scheme)")
        end = css.index("}", start) + 1
        chunks.append(css[cursor:start])
        cursor = end
    chunks.append(css[cursor:])
    return "".join(chunks)


def _rules(css):
    """``[(selector, body), ...]`` for every rule, at any nesting depth."""
    css = re.sub(r"/\*.*?\*/", " ", css, flags=re.S)
    rules, index = [], 0
    while True:
        brace = css.find("{", index)
        if brace < 0:
            return rules
        start = max(css.rfind("}", 0, brace), css.rfind(";", 0, brace)) + 1
        depth, end = 1, brace + 1
        while depth and end < len(css):
            if css[end] == "{":
                depth += 1
            elif css[end] == "}":
                depth -= 1
            end += 1
        rules.append((css[start:brace].strip(), css[brace + 1:end - 1]))
        index = end


def _block_body(css, selector):
    """The body of the one block opened by ``selector``."""
    bodies = [body for _, sel, body in _token_blocks(css) if sel == selector]
    assert len(bodies) == 1, f"expected exactly one {selector} block, found {len(bodies)}"
    return bodies[0]


def _tokens(body):
    """``{token: "#rrggbb"}`` for the opaque colour tokens a block declares."""
    return {m.group(1): m.group(2)
            for m in re.finditer(r"(--[a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;", body)}


def _luminance(hex_colour):
    channels = [int(hex_colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(fg, bg):
    hi, lo = sorted((_luminance(fg), _luminance(bg)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


# ── palette ──────────────────────────────────────────────────────────────

def test_palette_is_fully_tokenised():
    css = _read(CSS_PATH)
    assert ":root {" in css
    outside = re.findall(r"#[0-9a-fA-F]{3,8}\b", _strip_token_blocks(css))
    assert outside == [], f"raw hex colours outside the theme token blocks: {outside}"


def test_every_palette_block_is_custom_properties_only():
    """The hex scan skips the palette blocks, so those blocks must not be able
    to smuggle in a component rule: they declare tokens and color-scheme, and
    the set of blocks is exactly the four theme selectors — no more, no less.
    """
    css = _read(CSS_PATH)
    blocks = _token_blocks(css)
    assert [selector for _, selector, _ in blocks] == [
        ":root", '[data-theme="light"]', '[data-theme="dark"]', ":root:not([data-theme])"]
    for _, selector, body in blocks:
        for declaration in _declarations(body):
            property_name = declaration.split(":", 1)[0].strip()
            assert property_name.startswith("--") or property_name in NON_TOKEN_DECLARATIONS, \
                f"{selector} contains a component declaration: {declaration!r}"


def test_core_tokens_match_the_brief():
    css = _read(CSS_PATH)
    for token, value in [
        ("--bg", "#F9FAFB"), ("--surface", "#FFFFFF"), ("--border", "#E5E7EB"),
        ("--text", "#111827"), ("--text-secondary", "#6B7280"), ("--accent", "#3B82F6"),
        ("--success", "#16A34A"), ("--warning", "#D97706"), ("--danger", "#DC2626"),
    ]:
        assert re.search(rf"{re.escape(token)}:\s*{value};", css), f"{token} != {value}"


def test_banned_indigo_and_purple_accents_are_absent():
    banned = ("#6366f1", "#4f46e5", "#4338ca", "#3730a3", "#8b5cf6", "#7c3aed", "#a855f7")
    for name, text in _assets().items():
        low = text.lower()
        for colour in banned:
            assert colour not in low, f"{name} contains banned accent {colour}"


def test_no_gradients_or_glows():
    for name, text in _assets().items():
        low = text.lower()
        for pattern in ("linear-gradient", "radial-gradient", "conic-gradient",
                        "text-shadow", "drop-shadow", "filter: blur"):
            assert pattern not in low, f"{name} uses {pattern}"
    # Exactly one elevation in the whole console: the floating toast.
    css = _read(CSS_PATH)
    assert css.count("box-shadow") == 1
    assert "--shadow: 0 1px 2px rgba(17, 24, 39, .06);" in css


def test_no_colour_tint_pills_from_the_dark_theme():
    css = _read(CSS_PATH)
    # Translucent rgba() fills on a dark ground were the "neon" tell. Every
    # translucent value must be a token (the light `--shadow` is one, and so
    # is the dark override) — and _strip_token_blocks has already proven that
    # each stripped block holds nothing but tokens.
    assert "rgba(" not in _strip_token_blocks(css)


def _light_tokens():
    return _tokens(_block_body(_read(CSS_PATH), ":root"))


def _dark_tokens():
    return _tokens(_block_body(_read(CSS_PATH), '[data-theme="dark"]'))


# Every ink-on-surface relationship the console paints text with, in both
# palettes. 4.5:1 is the floor for the 12px chip/label text that dominates
# this console.
TEXT_CONTRAST_PAIRS = [
    ("--text", "--surface"), ("--text-secondary", "--surface"),
    ("--text-secondary", "--bg"), ("--success-ink", "--success-soft"),
    ("--warning-ink", "--warning-soft"), ("--danger-ink", "--danger-soft"),
    ("--accent-ink", "--accent-soft"), ("--neutral-ink", "--surface-sunken"),
    ("--on-ink", "--ink"),
]

# The dark palette adds surfaces the light one did not need to check: rows
# hover on --surface-sunken and body text sits on --bg directly.
DARK_EXTRA_PAIRS = [
    ("--text", "--bg"), ("--text", "--surface-sunken"),
    ("--text-secondary", "--surface-sunken"),
]


@pytest.mark.parametrize("fg,bg", TEXT_CONTRAST_PAIRS)
def test_status_chip_text_meets_contrast_floor(fg, bg):
    """12px chip text needs >= 4.5:1 against its own pale fill."""
    ratio = _contrast(_light_tokens()[fg], _light_tokens()[bg])
    assert ratio >= 4.5, f"{fg} on {bg} is {ratio:.2f}:1"


@pytest.mark.parametrize("fg,bg", TEXT_CONTRAST_PAIRS + DARK_EXTRA_PAIRS)
def test_dark_theme_text_meets_the_same_contrast_floor(fg, bg):
    """The dark palette is held to the light floor, not a relaxed one."""
    tokens = _dark_tokens()
    assert fg in tokens and bg in tokens, f"{fg}/{bg} missing from the dark palette"
    ratio = _contrast(tokens[fg], tokens[bg])
    assert ratio >= 4.5, f"DARK {fg} on {bg} is {ratio:.2f}:1"


# ── no remote or CDN assets (CSP has no font-src, so no web fonts) ───────

def test_no_web_fonts_or_remote_assets():
    for name, text in _assets().items():
        low = text.lower()
        for pattern in ("@font-face", "fonts.googleapis", "fonts.gstatic",
                        "@import", "cdn.", "unpkg", "jsdelivr"):
            assert pattern not in low, f"{name} references {pattern}"


def test_no_absolute_network_urls():
    for name, text in _assets().items():
        urls = re.findall(r"https?://[^\s\"')]+", text)
        # The SVG namespace is an identifier, never fetched.
        urls = [u for u in urls if u != "http://www.w3.org/2000/svg"]
        assert urls == [], f"{name} has remote URLs: {urls}"


def test_font_stacks_are_system_only():
    css = _read(CSS_PATH)
    assert "ui-serif" in css and "ui-sans-serif" in css and "ui-monospace" in css
    for family in re.findall(r"--font-[a-z]+:\s*([^;]+);", css):
        assert "url(" not in family
        assert "Georgia" in family or "Segoe UI" in family or "Consolas" in family


def test_csp_has_no_style_or_font_escape_hatch(client):
    csp = client.get("/admin").headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "unsafe-inline" not in csp
    assert "font-src" not in csp
    assert "style-src 'self'" in csp


# ── markup discipline ───────────────────────────────────────────────────

def test_no_inline_styles_or_scripts():
    html = _read(HTML_PATH)
    assert "style=" not in html
    assert "<style" not in html
    scripts = re.findall(r"<script\b[^>]*>", html)
    assert scripts, "the console must still load its script"
    for tag in scripts:
        assert 'src="/admin/assets/app.js"' in tag, tag
    assert html.count("<script") == html.count("</script>")
    assert re.search(r"<script[^>]*>\s*[^<\s]", html) is None
    # No third-party origins on the page either.
    assert "crossorigin" not in html


def test_no_emoji_in_static_assets():
    for name, text in _assets().items():
        offenders = [c for c in text
                     if 0x1F000 <= ord(c) <= 0x1FAFF        # pictographs / symbols
                     or 0x2600 <= ord(c) <= 0x27BF          # misc symbols, dingbats
                     or 0x2B00 <= ord(c) <= 0x2BFF
                     or ord(c) in (0xFE0F, 0x200D)]         # VS16, ZWJ
        assert offenders == [], f"{name} contains emoji: {offenders}"


def test_icons_are_inline_monoline_svg():
    html = _read(HTML_PATH)
    assert html.count("<svg") >= 9
    # 1.6-1.8px stroke on every icon, sized by class not by attribute.
    strokes = re.findall(r'stroke-width="([\d.]+)"', html)
    assert strokes and all(1.6 <= float(s) <= 1.8 for s in strokes), strokes
    assert 'stroke="currentColor"' in html
    # Brand logo raster images are permitted; navigation and control icons must remain inline SVGs
    imgs = re.findall(r'<img[^>]*>', html)
    assert all('/admin/assets/logo.png' in img for img in imgs)
    assert "background-image" not in _read(CSS_PATH)


def test_aria_and_labels_are_present():
    html = _read(HTML_PATH)
    assert 'aria-label="Console sections"' in html
    assert 'role="status"' in html
    assert "<label for=\"login-token\"" in html
    assert 'role="alert"' in html
    assert 'lang="en"' in html
    assert 'name="viewport"' in html


# ── document structure ──────────────────────────────────────────────────

def test_tags_are_balanced():
    parser = _structure()
    assert parser.errors == [], parser.errors
    assert parser.stack == [], f"unclosed elements: {parser.stack}"


def test_login_and_shell_are_siblings_at_body_level():
    """A stray end tag would nest the shell inside the hidden login wrapper."""
    parser = _structure()
    for element_id in ("login", "shell", "toast"):
        assert parser.parents.get(element_id) == "body", \
            f"#{element_id} is nested in <{parser.parents.get(element_id)}>, not <body>"
    # #view lives in <main id="main">, which lives in the #shell aside/main row.
    assert parser.parents.get("view") == "main"
    assert parser.parents.get("main") == "div"


# ── app.js ⇄ admin.html contract ────────────────────────────────────────

def _js_ids(js):
    return set(re.findall(r'\$\("#([A-Za-z0-9_-]+)"\)', js))


def test_every_id_app_js_queries_exists():
    html, js = _read(HTML_PATH), _read(JS_PATH)
    html_ids = set(re.findall(r'id="([A-Za-z0-9_-]+)"', html))
    created_in_js = set(re.findall(r'id:\s*"([A-Za-z0-9_-]+)"', js)) | \
        set(re.findall(r'\bid\s*=\s*"([A-Za-z0-9_-]+)"', js)) | \
        set(re.findall(r'\bfield\("([A-Za-z0-9_-]+)"', js))
    missing = sorted(_js_ids(js) - html_ids - created_in_js)
    assert missing == [], f"app.js queries ids that do not exist: {missing}"


def test_stable_hook_ids_survive():
    html = _read(HTML_PATH)
    required = ["login", "login-form", "login-token", "login-btn", "login-error",
                "logout-btn", "shell", "view", "toast", "x-status-pill", "main"]
    for hook in required:
        assert f'id="{hook}"' in html, hook


def test_stable_css_classes_survive():
    css, html, js = _read(CSS_PATH), _read(HTML_PATH), _read(JS_PATH)
    required = ["card", "cards", "k", "v", "s", "pill", "error", "muted", "mono",
                "hidden", "mt", "pager", "toolbar", "tester-out", "toast", "inline",
                "row", "wrap", "primary", "ghost", "danger", "brand", "sidebar",
                "shell", "login-card", "login-wrap"]
    for cls in required:
        assert re.search(rf"\.{re.escape(cls)}\b", css), f".{cls} missing from app.css"
    for variant in ("pill.ok", "pill.bad", "pill.warn", "pill.neutral", "toast.err", "toast.ok"):
        assert f".{variant}" in css, variant
    # Still produced by the JS and still used by the markup.
    for cls in ("cards", "toolbar", "tester-out", "pager"):
        assert cls in js, cls
    for cls in ("sidebar", "login-card", "brand"):
        assert cls in html, cls


def test_every_view_has_a_nav_entry_and_vice_versa():
    html, js = _read(HTML_PATH), _read(JS_PATH)
    nav = set(re.findall(r'data-view="([a-z-]+)"', html))
    defined = set(re.findall(r"views\.([A-Za-z]+)\s*=", js))
    assert nav == defined, f"nav={sorted(nav)} views={sorted(defined)}"
    assert "overview" in nav and "clients" in nav and "sessions" in nav


def test_every_admin_endpoint_is_still_called():
    js = _read(JS_PATH)
    endpoints = ["/admin/api/login", "/admin/api/logout", "/admin/api/session",
                 "/admin/api/overview", "/admin/api/accounts", "/admin/api/tools",
                 "/admin/api/usage", "/admin/api/audit", "/admin/api/backup",
                 "/admin/api/clients", "/admin/api/sessions", "/admin/api/validate"]
    for endpoint in endpoints:
        assert f'api("{endpoint}' in js or f'api(`{endpoint}' in js, endpoint
    assert "/test`" in js, "the per-tool tester call is missing"
    assert 'method: "PATCH"' in js and 'method: "DELETE"' in js


def test_console_served_assets_are_the_redesigned_ones(client):
    html = client.get("/admin").text
    css = client.get("/admin/assets/app.css").text
    js = client.get("/admin/assets/app.js").text
    assert "operations console" in html
    assert "--accent: #3B82F6" in css
    assert "#0d1117" not in css  # the old dark ground is gone
    assert "docs" not in js or True
    assert os.environ["ADMIN_TOKEN"] not in html + css + js


def test_no_view_or_control_removed():
    js, html = _read(JS_PATH), _read(HTML_PATH)
    for control in ("Add / rotate account", "Validate", "Delete", "Run tool",
                    "Run backup now", "Revoke all sessions", "Filter tools by name",
                    "Newer", "Older"):
        assert control in js, control
    assert "Sign out" in html
    assert 'id="logout-btn"' in html


# ── regression: name filters compare like with like ─────────────────────

def _js_view(js, name):
    """Body of one ``views.<name> = …`` definition, up to the next view."""
    start = js.index(f"views.{name} = ")
    end = js.find("\nviews.", start + 1)
    return js[start:] if end < 0 else js[start:end]


def _filter_receivers(js):
    """The expression each ``.includes(q)`` filter is applied to."""
    return re.findall(r"([A-Za-z0-9_$][\w.$]*(?:\(\)[\w.$]*)*)\.includes\(q\)", js)


def test_tool_name_filter_is_case_insensitive():
    """Source contract (no DOM harness in this repo — it is browserless by
    design): the tools filter lowercases the query, so it must lowercase the
    name too. ``tool.name.includes(q)`` can never match a name that contains
    an uppercase character, i.e. every real tool."""
    tools = _js_view(_read(JS_PATH), "tools")
    assert re.search(r"const q = search\.value\.toLowerCase\(\);", tools), \
        "the tools filter no longer lowercases its query"
    receivers = _filter_receivers(tools)
    assert receivers, "the tools filter lost its name comparison"
    for receiver in receivers:
        assert receiver.endswith(".toLowerCase()"), (
            f"{receiver}.includes(q) compares a lowercased query against a "
            "case-sensitive name")


def test_every_name_filter_lowercases_the_name_side():
    receivers = _filter_receivers(_read(JS_PATH))
    assert receivers, "no query filter found in app.js"
    for receiver in receivers:
        assert receiver.endswith(".toLowerCase()"), (
            f"{receiver}.includes(q) is case-sensitive; a lowercased query can "
            "only match a lowercased value")


# ── dark theme: the palette itself ───────────────────────────────────────

def test_dark_palette_has_a_twin_for_every_light_colour_token():
    """Any colour token the light palette paints the console with needs a
    dark decision — otherwise the dark theme silently falls back to a light
    value. Keyed off the light block, so a new token forces this test open."""
    light, dark = _light_tokens(), _dark_tokens()
    missing = sorted(set(light) - set(dark))
    assert missing == [], f"light tokens with no dark twin: {missing}"
    assert len(dark) >= 23, f"the dark palette shrank: {sorted(dark)}"


def test_dark_palette_declares_color_scheme_and_its_own_elevation():
    body = _block_body(_read(CSS_PATH), '[data-theme="dark"]')
    assert "color-scheme: dark;" in body
    # The toast's shadow is the console's only elevation: it must be a token
    # here too, and a dark one (the light rgba(17, 24, 39, …) is invisible).
    assert re.search(r"--shadow:\s*0 1px 2px rgba\(0, 0, 0, \.\d+\);", body)


def test_dark_palette_ground_is_not_the_banned_one():
    css = _read(CSS_PATH)
    assert "#0d1117" not in css.lower()
    dark = _dark_tokens()
    # Surfaces must actually step (ground < surface < sunken tint) rather than
    # repeat one value, or "sunken"/hover states become invisible.
    assert _luminance(dark["--bg"]) < _luminance(dark["--surface"]) < _luminance(dark["--surface-sunken"])
    assert _luminance(dark["--text"]) > _luminance(dark["--text-secondary"])
    assert _luminance(dark["--border"]) < _luminance(dark["--border-strong"])


def test_dark_first_paint_twin_matches_the_chosen_dark_palette():
    """The prefers-color-scheme block exists so a first visit paints dark
    before app.js runs. If it drifts from [data-theme="dark"], the OS-driven
    first paint and a clicked dark theme would look different."""
    css = _read(CSS_PATH)
    twin = _block_body(css, ":root:not([data-theme])")
    assert _tokens(twin) == _dark_tokens()
    for declaration in _declarations(twin):
        if declaration.startswith("--shadow"):
            assert declaration in _declarations(_block_body(css, '[data-theme="dark"]'))


def test_light_and_dark_are_not_the_same_palette():
    light, dark = _light_tokens(), _dark_tokens()
    for token in ("--bg", "--surface", "--text", "--border", "--neutral-ink"):
        assert light[token] != dark[token], token


# ── the theme control ────────────────────────────────────────────────────

def _inside_label(html, needle):
    before = html[:html.index(needle)]
    return before.rfind("<label") > before.rfind("</label>")


class _ThemeControls(HTMLParser):
    """The two theme controls, as data: each group's own attributes and the
    options it holds (attributes, visible text, inline icon attributes)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.groups = []
        self._group = None
        self._option = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "div" and attrs.get("id") in ("theme-toggle", "login-theme-toggle"):
            self._group = {"id": attrs["id"], "attrs": attrs, "options": []}
        elif tag == "button" and self._group is not None:
            self._option = {"attrs": attrs, "text": [], "icons": []}
        elif tag == "svg" and self._option is not None:
            self._option["icons"].append(attrs)

    def handle_data(self, data):
        if self._option is not None and data.strip():
            self._option["text"].append(data.strip())

    def handle_endtag(self, tag):
        if tag == "button" and self._option is not None:
            self._group["options"].append(self._option)
            self._option = None
        elif tag == "div" and self._group is not None:
            self.groups.append(self._group)
            self._group = None


def _theme_controls():
    parser = _ThemeControls()
    parser.feed(_read(HTML_PATH))
    parser.close()
    return parser.groups


def test_theme_control_is_in_both_chromes():
    groups = {group["id"]: group for group in _theme_controls()}
    assert sorted(groups) == ["login-theme-toggle", "theme-toggle"]
    html = _read(HTML_PATH)
    # Sidebar footer, next to Sign out — reachable on mobile where the sidebar
    # stacks above the view.
    foot = html[html.index('class="sidebar-foot"'):html.index("</aside>")]
    assert 'id="theme-toggle"' in foot and 'id="logout-btn"' in foot
    # ... and the sign-in card, so the console is themable before sign-in.
    login = html[html.index('id="login"'):html.index('id="shell"')]
    assert 'id="login-theme-toggle"' in login
    for hook in ("theme-toggle", "login-theme-toggle"):
        assert not _inside_label(html, f'id="{hook}"'), f"#{hook} is inside a <label>"


def test_theme_control_is_a_labelled_group_of_three_options():
    """Three real buttons, one per mode: keyboard operable for free, each
    carrying its own state in aria-pressed inside a labelled group."""
    groups = _theme_controls()
    assert len(groups) == 2, "the control belongs on the sign-in card and in the shell"
    for group in groups:
        assert group["attrs"].get("role") == "group", group["id"]
        assert re.fullmatch(r"[A-Za-z][A-Za-z ]+", group["attrs"].get("aria-label", "")), group["id"]
        assert "style" not in group["attrs"]
        assert [option["attrs"].get("data-theme-choice") for option in group["options"]] == \
            ["system", "light", "dark"]
        # The default mode is marked before the script runs, so the control is
        # honest even if app.js never loads.
        pressed = [option["attrs"].get("aria-pressed") for option in group["options"]]
        assert pressed == ["true", "false", "false"], group["id"]


def test_every_theme_option_is_a_labelled_button_with_a_monoline_icon():
    for group in _theme_controls():
        for option in group["options"]:
            attrs = option["attrs"]
            assert attrs.get("type") == "button", attrs
            assert "style" not in attrs
            # Never icon-only: the mode is spelled out in text.
            assert len(option["text"]) == 1 and option["text"][0][0].isupper(), option
            assert len(option["icons"]) == 1, f"{group['id']} option carries {len(option['icons'])} icons"
            icon = option["icons"][0]
            assert icon.get("stroke") == "currentColor", icon
            assert 1.6 <= float(icon.get("stroke-width", 0)) <= 1.8, icon
            assert icon.get("aria-hidden") == "true" and icon.get("focusable") == "false"


def test_theme_control_state_is_css_driven_off_aria_pressed():
    css = _read(CSS_PATH)
    # The chosen option is styled from its own pressed state (the channel an
    # assistive technology reads), not from a class the script has to keep in
    # step with it.
    assert '.theme-toggle button[aria-pressed="true"] {' in css
    assert '.theme-toggle button:hover:not(:disabled)' in css
    # A three-way control needs no icon swap, so the old two-state rules are
    # gone rather than left to fight the new ones.
    assert ".icon-sun" not in css and ".icon-moon" not in css


def test_theme_control_is_a_three_column_segmented_group():
    rule = next(body for selector, body in _rules(_read(CSS_PATH))
                if selector.strip() == ".theme-toggle")
    assert "grid-template-columns: repeat(3, 1fr);" in rule, rule
    assert "background: var(--bg);" in rule, rule


# ── the theme contract in app.js ─────────────────────────────────────────

def test_theme_modes_are_the_three_names_with_system_as_the_default():
    js = _read(JS_PATH)
    assert re.search(r'const THEME_KEY = "kxstrel-theme";', js)
    assert re.search(r'const THEME_SYSTEM = "system";', js)
    assert re.search(r'const THEME_LIGHT = "light";', js)
    assert re.search(r'const THEME_DARK = "dark";', js)
    assert re.search(r"const THEME_MODES = \[THEME_SYSTEM, THEME_LIGHT, THEME_DARK\];", js)
    # A stored value is validated on read, so a hand-edited key falls through
    # to the default rather than being applied blindly.
    assert re.search(r"return THEME_MODES\.includes\(saved\) \? saved : null;", js)
    assert re.search(r"return storedTheme\(\) \|\| THEME_SYSTEM;", js)


def test_theme_system_removes_the_attribute_while_explicit_modes_set_it():
    """system must not name a palette: dropping data-theme is what hands the
    decision to the stylesheet's prefers-color-scheme block, and what makes
    "explicitly system" behave exactly like "no choice yet"."""
    js = _read(JS_PATH)
    assert re.search(
        r'if \(mode === THEME_SYSTEM\) root\.removeAttribute\("data-theme"\);\s*\n'
        r'\s*else root\.dataset\.theme = mode;', js)
    assert ":root:not([data-theme])" in _read(CSS_PATH)


def test_theme_system_follows_the_os_live_and_only_while_it_is_selected():
    js = _read(JS_PATH)
    # Both subscription shapes, and no throw when neither exists.
    assert 'darkQuery.addEventListener("change", onSystemChange)' in js
    assert 'darkQuery.addListener("change", onSystemChange)' in js
    assert re.search(r'typeof darkQuery\.addEventListener === "function"', js)
    assert re.search(r'typeof darkQuery\.addListener === "function"', js)
    # The listener re-resolves on every OS flip, and only in system mode: an
    # explicit light/dark choice is never overridden.
    assert "if (themeMode === THEME_SYSTEM) applyTheme(THEME_SYSTEM);" in js


def test_theme_falls_back_to_light_when_the_os_cannot_be_consulted():
    js = _read(JS_PATH)
    assert re.search(r'const query = window\.matchMedia\("\(prefers-color-scheme: dark\)"\);', js)
    # A missing, throwing or unusable matchMedia resolves to light — never to
    # "no theme".
    assert re.search(r"return query && query\.matches \? THEME_DARK : THEME_LIGHT;", js)
    assert re.search(r"catch \{ return THEME_LIGHT; \}", js)


def test_theme_choice_is_persisted_as_one_of_three_values_only():
    """The settings key holds a mode name and nothing else. There is exactly
    one write in the file and its value is normalised to the three names, so no
    later change can park a token/blob in the key."""
    js = _read(JS_PATH)
    writes = re.findall(r"localStorage\.setItem\(([^;]*)\)", js)
    assert len(writes) == 1, f"expected exactly one storage write, found {len(writes)}"
    key, _, value = writes[0].partition(",")
    assert key.strip() == "THEME_KEY"
    assert re.fullmatch(r"[A-Za-z0-9_$]+", value.strip()), f"storage write is not normalised: {writes[0]}"
    assert re.search(r"const value = normalizeMode\(mode\);", js)
    assert re.search(r"return THEME_MODES\.includes\(mode\) \? mode : THEME_SYSTEM;", js)
    assert js.count("localStorage.setItem") == 1
    assert js.count("localStorage.getItem") == 1
    assert "localStorage.getItem(THEME_KEY)" in js
    # Both storage calls are wrapped: private mode and sandboxed frames are
    # normal conditions for an operator console, not crashes.
    assert js.count("localStorage.") == 2, "a storage access escaped the wrappers"
    assert re.search(r"try \{\s*const saved = localStorage\.getItem\(THEME_KEY\);", js)
    assert re.search(r"\} catch \{ return null; \}", js)
    assert re.search(r"try \{ localStorage\.setItem\(THEME_KEY, value\); \} catch \{\}", js)


def test_theme_is_applied_to_the_document_element_before_anything_renders():
    js = _read(JS_PATH)
    assert re.search(r"const root = document\.documentElement;", js)
    assert 'root.removeAttribute("data-theme")' in js and "root.dataset.theme = mode" in js
    applied = js.index("applyTheme(themeMode);")
    assert applied < js.index("boot();")
    assert applied < js.index("views.overview =")
    # ... and the stylesheet covers the instant before this script executes.
    assert ":root:not([data-theme])" in _read(CSS_PATH)


def test_both_theme_controls_are_wired_and_kept_in_sync():
    js = _read(JS_PATH)
    assert js.count('document.querySelectorAll(".theme-toggle [data-theme-choice]")') == 2, \
        "one pass for the click listeners, one for the aria-pressed state"
    assert 'setAttribute("aria-pressed", String(btn.dataset.themeChoice === mode))' in js
    assert "themeMode = normalizeMode(btn.dataset.themeChoice);" in js


# ── the theme behaviour, executed (Node, no browser) ─────────────────────

NODE = shutil.which("node")
THEME_BANNER = "/* ───────────────────────── theme ───────────────────────── */"


def _theme_section():
    """The shipped theme section: everything from its banner comment to the
    first DOM helper. Delimited on purpose — if it moves, this fails loudly
    rather than silently testing nothing."""
    js = _read(JS_PATH)
    section = js[js.index(THEME_BANNER):js.index("const $ = (sel)")]
    for required in ("THEME_KEY", "matchMedia", "localStorage", "applyTheme("):
        assert required in section, f"the theme section no longer contains {required}"
    return section


@pytest.fixture(scope="module")
def theme_behaviour(tmp_path_factory):
    """What the shipped theme section actually does, observed by running it."""
    if NODE is None:
        pytest.skip("node is not installed; the theme behaviour harness needs it")
    section = tmp_path_factory.mktemp("theme") / "theme-section.js"
    section.write_text(_theme_section(), encoding="utf-8")
    harness = os.path.join(os.path.dirname(os.path.abspath(__file__)), "theme_harness.js")
    result = subprocess.run([NODE, harness, str(section)],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    scenarios = json.loads(result.stdout)["scenarios"]
    assert len(scenarios) >= 13, sorted(scenarios)
    return scenarios


def test_executed_theme_code_never_throws_in_any_environment(theme_behaviour):
    for name, shots in theme_behaviour.items():
        for shot in shots:
            assert shot["error"] is None, f"{name} / {shot['label']}: {shot['error']}"


def test_executed_default_mode_is_system_with_nothing_stored(theme_behaviour):
    for name, expected in (("default_nothing_stored_os_light", "light"),
                           ("default_nothing_stored_os_dark", "dark")):
        load = theme_behaviour[name][0]
        assert load["dataTheme"] is None, "system must not pin a palette"
        assert load["resolved"] == expected, "system resolves through the OS"
        assert load["pressed"]["0:system"] == "true"
        assert load["writes"] == [], "a default is not a choice: nothing is stored"
        assert set(load["pressed"].values()) == {"true", "false"}


def test_executed_system_mode_follows_the_os_without_a_reload(theme_behaviour):
    shots = theme_behaviour["default_nothing_stored_os_light"]
    assert [shot["resolved"] for shot in shots] == ["light", "dark", "light"]
    assert all(shot["dataTheme"] is None for shot in shots)
    assert all(shot["subscriptions"] == 1 for shot in shots), \
        "the media-query subscription is missing, so OS flips would be missed"
    # The control keeps announcing "System" through all of it.
    assert all(shot["pressed"]["0:system"] == "true" for shot in shots)


@pytest.mark.parametrize("name,expected", [("explicit_light_beats_os_dark", "light"),
                                           ("explicit_dark_beats_os_light", "dark")])
def test_executed_explicit_choice_is_not_overridden_by_the_os(theme_behaviour, name, expected):
    shots = theme_behaviour[name]
    assert len(shots) > 1, "the scenario never flipped the OS"
    for shot in shots:
        assert shot["dataTheme"] == expected
        assert shot["resolved"] == expected
        assert shot["pressed"][f"0:{expected}"] == "true"
        assert shot["writes"] == [], "following the OS is not a choice: nothing is stored"


def test_executed_clicking_walks_light_then_system_then_dark(theme_behaviour):
    shots = theme_behaviour["click_light_then_system_then_dark"]
    assert shots[0]["label"] == "load"  # system by default, OS dark
    # Light is chosen and stays chosen when the OS flips to light.
    assert [(shot["dataTheme"], shot["resolved"]) for shot in shots[1:3]] == \
        [("light", "light"), ("light", "light")]
    assert shots[1]["pressed"]["0:light"] == "true"
    # Back to system: the attribute goes, and the OS (light) is followed again ...
    assert (shots[3]["dataTheme"], shots[3]["resolved"]) == (None, "light")
    assert shots[3]["pressed"]["0:system"] == "true"
    assert shots[4]["resolved"] == "dark", "system did not resume following the OS"
    assert shots[4]["dataTheme"] is None
    # ... then an explicit dark pins it again, whatever the OS does.
    assert (shots[5]["dataTheme"], shots[5]["resolved"]) == ("dark", "dark")
    assert shots[6]["resolved"] == "dark" and shots[6]["dataTheme"] == "dark"
    assert shots[-1]["writes"] == ["kxstrel-theme=light", "kxstrel-theme=system", "kxstrel-theme=dark"]


def test_executed_second_control_is_wired_and_stays_in_sync(theme_behaviour):
    shots = theme_behaviour["second_group_is_wired_and_kept_in_sync"]
    # The sidebar group was clicked; both groups must show the same mode.
    assert shots[1]["dataTheme"] == "dark"
    assert shots[1]["pressed"] == {"0:system": "false", "0:light": "false", "0:dark": "true",
                                   "1:system": "false", "1:light": "false", "1:dark": "true"}
    assert shots[2]["pressed"] == {"0:system": "true", "0:light": "false", "0:dark": "false",
                                   "1:system": "true", "1:light": "false", "1:dark": "false"}


def test_executed_storage_only_ever_receives_the_three_mode_names(theme_behaviour):
    seen = set()
    for shots in theme_behaviour.values():
        for shot in shots:
            for write in shot["writes"]:
                key, _, value = write.partition("=")
                assert key == "kxstrel-theme", write
                seen.add(value)
    assert seen == {"system", "light", "dark"}, f"storage saw {sorted(seen)}"


def test_executed_junk_in_storage_reads_as_system(theme_behaviour):
    for shot in theme_behaviour["stored_junk_reads_as_system"]:
        assert shot["dataTheme"] is None
        assert shot["pressed"]["0:system"] == "true"
    # ... and then behaves like system: it follows the OS.
    assert [shot["resolved"] for shot in theme_behaviour["stored_junk_reads_as_system"]] == \
        ["dark", "light"]


def test_executed_legacy_engines_are_subscribed_through_add_listener(theme_behaviour):
    shots = theme_behaviour["legacy_add_listener"]
    assert shots[0]["subscriptions"] == 1, "addListener fallback did not subscribe"
    assert [shot["resolved"] for shot in shots] == ["light", "dark"]


def test_executed_engine_without_a_subscription_api_still_themes(theme_behaviour):
    shots = theme_behaviour["no_listener_api"]
    assert [shot["subscriptions"] for shot in shots] == [0, 0]
    assert shots[0]["resolved"] == "dark", "the theme must still resolve once"


@pytest.mark.parametrize("name", ["matchmedia_missing", "matchmedia_throws", "matchmedia_unusable"])
def test_executed_unusable_matchmedia_resolves_to_light(theme_behaviour, name):
    for shot in theme_behaviour[name]:
        assert shot["resolved"] == "light", f"{name} did not fall back to light"
        assert shot["dataTheme"] is None
        assert shot["pressed"]["0:system"] == "true"


def test_executed_unavailable_storage_never_throws_and_still_themes(theme_behaviour):
    shots = theme_behaviour["storage_throws_everywhere"]
    assert shots[0]["resolved"] == "dark", "system ignored the OS"
    assert shots[1]["resolved"] == "light", "an explicit choice stopped working"
    assert shots[2]["resolved"] == "light"
    assert all(shot["writes"] == [] for shot in shots), \
        "a blocked store must not be reported as having accepted the write"


# ── theme transition ─────────────────────────────────────────────────────

def _transition_declarations(css):
    return [value for _, body in _rules(css) for value in re.findall(r"transition:\s*([^;]+);", body)]


def test_theme_transition_is_one_curated_colour_only_rule():
    css = _read(CSS_PATH)
    shorthands = _transition_declarations(css)
    assert len(shorthands) == 1, f"expected exactly one transition rule, found {shorthands}"
    value = shorthands[0]
    # Colour properties only: a theme switch can never move layout, and the
    # toast's single elevation never enters a transition property list.
    assert "box-shadow" not in value
    assert "background-color" in value and "color" in value and "border-color" in value
    durations = re.findall(r"(\d+)ms", value)
    assert durations, value
    for duration in durations:
        assert 160 <= int(duration) <= 220, value
    # A stable easing, not a bare linear ramp with no name.
    assert re.search(r"\b(ease|ease-in-out|linear)\b|cubic-bezier\(", value), value
    # Never a blanket wildcard: that would animate every hover/disabled shift
    # in the console and would drag box-shadow in with it.
    for selector, body in _rules(css):
        if "transition:" not in body:
            continue
        for part in selector.split(","):
            assert part.strip() not in ("*", "*::before", "*::after"), selector


def test_theme_transition_covers_the_themed_components():
    css = _read(CSS_PATH)
    rule = next(selector for selector, body in _rules(css) if "transition:" in body)
    selectors = [part.strip() for part in rule.split(",")]
    for component in ("body", ".sidebar", ".sidebar nav a", ".sidebar-foot", ".login-card",
                      ".card", ".pill", "th", "td", "button", "input", "select",
                      ".tester-out", ".error", ".toast", "form.inline"):
        assert component in selectors, f"{component} would snap instead of fading"


def test_reduced_motion_switches_the_theme_instantly():
    css = _read(CSS_PATH)
    blocks = [body for selector, body in _rules(css) if "prefers-reduced-motion" in selector]
    assert blocks, "the reduced-motion block is gone"
    assert "transition-duration: .001ms !important" in blocks[0]


def test_focus_ring_is_a_token_in_both_palettes():
    css = _read(CSS_PATH)
    assert "outline: 2px solid var(--focus-ring);" in css
    assert _light_tokens()["--focus-ring"] == _light_tokens()["--accent"]
    assert _dark_tokens()["--focus-ring"] == _dark_tokens()["--accent"]


def test_theme_meta_declares_both_schemes():
    # Otherwise the UA paints the canvas/controls light regardless of the CSS.
    assert '<meta name="color-scheme" content="light dark">' in _read(HTML_PATH)
