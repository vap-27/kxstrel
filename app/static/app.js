/* Kxstrel X MCP operations console. Vanilla JS, no external deps, CSP-safe.
   The admin token is used exactly once (login POST) and never stored:
   subsequent calls ride the HttpOnly session cookie. */
"use strict";

/* ───────────────────────── theme ───────────────────────── */

/* Three-mode contract: the operator picks "system" (the default), "light" or
   "dark". An explicit choice is mirrored onto <html data-theme> and persisted
   under a single localStorage key; "system" removes the attribute instead, so
   the stylesheet's prefers-color-scheme block governs — and keeps governing
   when the OS flips. Nothing else is ever written to that key (see
   persistTheme), so it cannot become a place to park unrelated state. */
const THEME_KEY = "kxstrel-theme";
const THEME_SYSTEM = "system";
const THEME_LIGHT = "light";
const THEME_DARK = "dark";
const THEME_MODES = [THEME_SYSTEM, THEME_LIGHT, THEME_DARK];

/* Anything outside the three mode names is system, so the attribute and the
   storage key can never hold a value the stylesheet does not know. */
function normalizeMode(mode) {
  return THEME_MODES.includes(mode) ? mode : THEME_SYSTEM;
}

function storedTheme() {
  try {
    const saved = localStorage.getItem(THEME_KEY);
    return THEME_MODES.includes(saved) ? saved : null;
  } catch { return null; }  // storage blocked (private mode, policy) -> follow the OS
}

/* The OS preference, and only the OS preference. A missing, throwing or
   unusable matchMedia means the OS cannot be consulted at all — light is the
   documented fallback then, never "no theme". */
function systemTheme() {
  try {
    const query = window.matchMedia("(prefers-color-scheme: dark)");
    return query && query.matches ? THEME_DARK : THEME_LIGHT;
  } catch { return THEME_LIGHT; }
}

/* The mode the console is in: an explicit choice, else system. */
function currentMode() {
  return storedTheme() || THEME_SYSTEM;
}

/* The mode resolved to the palette actually painted: system defers to the OS. */
function resolveTheme(mode) {
  return mode === THEME_SYSTEM ? systemTheme() : mode;
}

/* The only storage write in this file, and it normalises right here: whatever
   the caller passes, storage only ever sees "system", "light" or "dark". */
function persistTheme(mode) {
  const value = normalizeMode(mode);
  try { localStorage.setItem(THEME_KEY, value); } catch {}
}

function applyTheme(mode) {
  const root = document.documentElement;
  /* System names no palette: dropping the attribute hands the decision to the
     prefers-color-scheme block, which then repaints on its own when the OS
     flips. Light and dark pin the palette explicitly, overriding the query. */
  if (mode === THEME_SYSTEM) root.removeAttribute("data-theme");
  else root.dataset.theme = mode;
  /* The resolved palette, mirrored for tooling — CSS never keys off this, it
     is what the media query is for. */
  root.dataset.themeResolved = resolveTheme(mode);
  /* The options carry their own state in aria-pressed, so the active mode is
     programmatically determinable without relying on colour or an icon. */
  document.querySelectorAll(".theme-toggle [data-theme-choice]").forEach((btn) => {
    btn.setAttribute("aria-pressed", String(btn.dataset.themeChoice === mode));
  });
}

/* Applied before anything else in this file runs, so the console paints in
   the right theme: app.css carries the same palette under
   :root:not([data-theme]) for the instant before this script executes. */
let themeMode = currentMode();
applyTheme(themeMode);

/* Two controls, one behaviour: the sidebar footer and the sign-in card, so the
   console is themable before anyone signs in. */
document.querySelectorAll(".theme-toggle [data-theme-choice]").forEach((btn) => {
  btn.addEventListener("click", () => {
    themeMode = normalizeMode(btn.dataset.themeChoice);
    persistTheme(themeMode);
    applyTheme(themeMode);
  });
});

/* System mode follows the OS for the life of the page: the media-query
   listener re-resolves on every flip, and only while the mode is system — an
   explicit light/dark choice is never overridden. Older engines expose
   addListener instead of addEventListener; an engine with neither keeps the
   theme it resolved on load rather than throwing. */
try {
  const darkQuery = window.matchMedia("(prefers-color-scheme: dark)");
  const onSystemChange = () => { if (themeMode === THEME_SYSTEM) applyTheme(THEME_SYSTEM); };
  if (darkQuery && typeof darkQuery.addEventListener === "function") {
    darkQuery.addEventListener("change", onSystemChange);
  } else if (darkQuery && typeof darkQuery.addListener === "function") {
    darkQuery.addListener("change", onSystemChange);
  }
} catch {}

const $ = (sel) => document.querySelector(sel);
const el = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const child of children) if (child) node.append(child);
  return node;
};

const SVG_NS = "http://www.w3.org/2000/svg";

/* Inline monoline icons (1.7px stroke, currentColor) — the same vocabulary
   as the static SVGs in admin.html. No emoji, no external assets. */
function svgIcon(paths, cls = "btn-icon") {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", cls);
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.7");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  for (const d of paths) {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}
const ICON_LEFT = ["M14 6l-6 6 6 6"];
const ICON_RIGHT = ["M10 6l6 6-6 6"];

/* Shared markup helpers: tables always carry a label and scoped headers,
   empty states are announced as such, loading states are explicit. */
const pageTitle = (text) => el("h2", { text });
const loading = (what) => el("p", { class: "muted loading", text: `Loading ${what}…` });
const table = (label) => el("table", { "aria-label": label });
const th = (text) => el("th", { scope: "col", text });
const td = (text, cls) => el("td", cls ? { class: cls, text } : { text });
const emptyRow = (cols, text) =>
  el("tr", {}, el("td", { colspan: String(cols), class: "muted empty", text }));
const field = (id, labelText, placeholder, type = "text") =>
  el("div", { class: "field" },
    el("label", { for: id, text: labelText }),
    el("input", { id, type, placeholder, required: "", autocomplete: "off" }));

async function api(path, opts = {}) {
  const { headers: extraHeaders = {}, ...requestOptions } = opts;
  const resp = await fetch(path, {
    credentials: "same-origin",
    ...requestOptions,
    headers: { "X-Requested-With": "XMLHttpRequest", ...(opts.body ? { "Content-Type": "application/json" } : {}), ...extraHeaders },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (resp.status === 401) { showLogin(); throw new Error("unauthorized"); }
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error?.message || `HTTP ${resp.status}`);
  return data;
}

let toastTimer;
let renderVersion = 0;
let statusPollTimer = null;
let serverClockOffsetMs = 0;

function showViewError(title, error) {
  const v = $("#view");
  v.replaceChildren(el("h2", { text: title }),
    el("p", { class: "error", role: "alert", text: error.message || "Request failed" }));
}

function isCurrentRender(version) {
  return version === renderVersion;
}

function toast(msg, kind = "info") {
  const t = $("#toast");
  t.textContent = msg;
  t.className = `toast ${kind === "error" ? "err" : kind === "ok" ? "ok" : ""}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 4000);
}

function statusPill(status) {
  const map = {
    CONNECTED: ["ok", "CONNECTED"], INVALID_SESSION: ["bad", "INVALID SESSION"],
    RATE_LIMITED: ["warn", "RATE LIMITED"], X_UNAVAILABLE: ["warn", "X UNAVAILABLE"],
    CONFIG_ERROR: ["bad", "CONFIG ERROR"], NOT_CONFIGURED: ["neutral", "NOT CONFIGURED"],
  };
  const [cls, label] = map[status] || ["neutral", status];
  return el("span", { class: `pill ${cls}`, text: label });
}

const fmtTime = (iso) => {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
};

/* ───────────────────────── login / shell ───────────────────────── */

function showLogin() {
  if (statusPollTimer !== null) {
    clearInterval(statusPollTimer);
    statusPollTimer = null;
  }
  $("#shell").classList.add("hidden");
  $("#login").classList.remove("hidden");
  $("#login-token").focus();
}

async function boot() {
  try {
    const s = await api("/admin/api/session");
    if (s.authenticated) showShell(); else showLogin();
  } catch { showLogin(); }
}

function showShell() {
  $("#login").classList.add("hidden");
  $("#shell").classList.remove("hidden");
  refreshStatusPill();
  if (statusPollTimer === null) statusPollTimer = setInterval(refreshStatusPill, 60000);
  route();
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#login-btn");
  btn.disabled = true;
  btn.textContent = "Signing in…";
  $("#login-error").classList.add("hidden");
  try {
    await api("/admin/api/login", { method: "POST", body: { token: $("#login-token").value } });
    $("#login-token").value = "";
    showShell();
  } catch (err) {
    const box = $("#login-error");
    box.textContent = "Login failed: " + err.message;
    box.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    btn.textContent = "Sign in";
  }
});

$("#logout-btn").addEventListener("click", async () => {
  try { await api("/admin/api/logout", { method: "POST" }); } catch {}
  showLogin();
});

/* ───────────────────────── routing ───────────────────────── */

const views = {};
function route() {
  const name = (location.hash || "#/overview").slice(2);
  const view = Object.prototype.hasOwnProperty.call(views, name) ? name : "overview";
  const version = ++renderVersion;
  document.querySelectorAll(".sidebar nav a").forEach((a) => {
    const current = a.dataset.view === view;
    a.classList.toggle("active", current);
    if (current) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  document.title = `Kxstrel X MCP · ${view}`;
  Promise.resolve(views[view](version)).catch((error) => {
    if (isCurrentRender(version)) showViewError(view, error);
  });
}

window.addEventListener("hashchange", route);

async function refreshStatusPill() {
  try {
    const s = await api("/admin/api/overview");
    const pill = $("#x-status-pill");
    pill.replaceWith(Object.assign(statusPill(s.x_status), { id: "x-status-pill" }));
  } catch {}
}

/* ───────────────────────── uptime helpers ───────────────────────── */

function fmtDuration(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (d) return `${d}d ${h}h ${m}m ${sec}s`;
  if (h) return `${h}h ${m}m ${sec}s`;
  if (m) return `${m}m ${sec}s`;
  return `${sec}s`;
}

/* Live-ticking uptime displays anchored to server timestamps: the page
   can refresh any time — the value comes from persisted server state,
   and JS only interpolates the passage of time between polls. */
const uptimeAnchors = [];  // {el, iso}
function tickUptimes() {
  const now = Date.now() + serverClockOffsetMs;
  for (const a of uptimeAnchors) {
    if (!document.body.contains(a.el)) continue;
    const start = Date.parse(a.iso);
    if (Number.isNaN(start)) continue;
    a.el.textContent = fmtDuration(now - start);
  }
}
setInterval(tickUptimes, 1000);

function liveUptime(iso) {
  const span = el("span", { class: "v mono", text: "…" });
  if (iso) uptimeAnchors.push({ el: span, iso });
  else span.textContent = "—";
  return span;
}

/* ───────────────────────── overview ───────────────────────── */

views.overview = async (version = renderVersion) => {
  const v = $("#view");
  v.replaceChildren(pageTitle("Overview"), loading("system state"));
  let d;
  try { d = await api("/admin/api/overview"); }
  catch (e) { if (isCurrentRender(version)) showViewError("Overview", e); return; }
  if (!isCurrentRender(version)) return;

  uptimeAnchors.length = 0;
  if (d.server_now) serverClockOffsetMs = Date.parse(d.server_now) - Date.now();
  const cards = el("div", { class: "cards" });
  cards.append(
    card("Site uptime", liveUptime(d.service_first_started_at),
      `since ${fmtTime(d.service_first_started_at)} · persists across restarts`),
    card("MCP uptime", liveUptime(d.mcp_first_ok_at),
      `endpoint live since ${fmtTime(d.mcp_first_ok_at)}`),
    card("Process uptime", liveUptime(d.started_at),
      `current instance · ${fmtTime(d.started_at)}`),
    card("X session", statusPill(d.x_status), `checked ${fmtTime(d.last_checked_at)}`),
    card("Database", el("span", { text: d.db_ok ? "OK" : "DOWN", class: d.db_ok ? "pill ok" : "pill bad" }), d.db_backend),
    card("MCP clients", el("span", { text: String(d.mcp_client_count) }),
      d.mcp_clients.length ? d.mcp_clients.map((c) => c.name).join(", ") : "no handshakes yet"),
    card("Accounts", el("span", { text: `${d.accounts_enabled}/${d.accounts_configured}` }), "enabled / configured"),
    card("Backup", backupChip(d.backup.ok), fmtTime(d.backup.last_backup_at)),
  );
  v.replaceChildren(pageTitle("Overview"), cards);
  // Register anchors before rendering and tick once immediately. Do not
  // clear them here: the one-second ticker owns this registry.
  tickUptimes();

  if (!d.accounts_configured) {
    v.append(
      el("h3", { text: "Connect your first X account" }),
      el("p", { class: "muted", text: "No X account is configured yet. AI clients cannot call Twitter/X tools until at least one account is configured. Add your account credentials below or manage them in the Accounts tab:" })
    );
    const qForm = el("form", { class: "inline", id: "quick-acct-form" });
    qForm.append(
      el("div", { class: "row" },
        field("q-label", "Label", "myaccount"),
        field("q-auth", "auth_token", "X session auth token", "password"),
        field("q-ct0", "ct0", "160-char ct0 token", "password"),
        el("button", { class: "primary", type: "submit", text: "Add & connect account" })
      )
    );
    qForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const res = await api("/admin/api/accounts", {
          method: "POST",
          body: {
            label: $("#q-label").value.trim(),
            auth_token: $("#q-auth").value.trim(),
            ct0: $("#q-ct0").value.trim(),
            enabled: true,
          },
        });
        toast(`Account saved — X status: ${res.x_status}`, res.x_status === "CONNECTED" ? "ok" : "error");
        (res.warnings || []).forEach((w) => toast("Warning: " + w, "error"));
        route();
      } catch (err) { toast(err.message, "error"); }
    });
    v.append(qForm);
  }

  if (d.last_error) {
    v.append(el("p", { class: "muted", text: "Last error: " + d.last_error }));
  }
  const top = d.usage_7d?.top_tools || [];
  if (top.length) {
    const t = table("Top tools by calls, last 7 days");
    t.append(el("thead", {}, el("tr", {}, th("Tool"), th("Calls (7d)"))));
    const tb = el("tbody");
    for (const row of top) tb.append(el("tr", {}, td(row.tool_name, "mono"), td(String(row.calls))));
    t.append(tb);
    v.append(el("h3", { text: "Top tools (7 days)" }), t);
  }
  v.append(el("p", { class: "muted mt", text: "Live client identities, per-tool state and call history are under MCP clients, Tools and Usage logs." }));
};

function card(k, value, sub) {
  return el("div", { class: "card" },
    el("div", { class: "k", text: k }),
    el("div", { class: "v" }, value),
    el("div", { class: "s", text: sub || "" }));
}

/* Backup state is tri-state (never run / ok / failing); "never run" is a real
   state and gets words rather than a bare dash so the chip never reads as an
   empty value. */
function backupChip(ok) {
  const cls = ok === null ? "neutral" : ok ? "ok" : "bad";
  const text = ok === null ? "NOT RUN YET" : ok ? "OK" : "FAILING";
  return el("span", { class: `pill ${cls}`, text });
}

/* ───────────────────────── accounts ───────────────────────── */

views.accounts = async (version = renderVersion) => {
  const v = $("#view");
  v.replaceChildren(pageTitle("Accounts"), loading("accounts"));

  const form = el("form", { class: "inline", id: "acct-form" });
  form.append(
    el("div", { class: "row" },
      field("f-label", "Label", "myaccount"),
      field("f-auth", "auth_token", "X session auth token", "password"),
      field("f-ct0", "ct0", "X session ct0 token", "password"),
      el("button", { class: "primary", type: "submit", text: "Add / rotate account" })));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const res = await api("/admin/api/accounts", {
        method: "POST",
        body: {
          label: $("#f-label").value.trim(),
          auth_token: $("#f-auth").value.trim(),
          ct0: $("#f-ct0").value.trim(),
          enabled: true,
        },
      });
      toast(`Account saved — X status: ${res.x_status}`, res.x_status === "CONNECTED" ? "ok" : "error");
      (res.warnings || []).forEach((w) => toast("Warning: " + w, "error"));
      form.reset();
      route();
    } catch (err) { toast(err.message, "error"); }
  });

  let data = { accounts: [] };
  let loadError = null;
  try { data = await api("/admin/api/accounts"); }
  catch (e) { loadError = e; }
  if (!isCurrentRender(version)) return;

  const t = table("Configured X accounts");
  t.append(el("thead", {}, el("tr", {},
    th("Label"), th("Enabled"), th("Status"), th("Last check"), th("Last error"), th("Actions"))));
  const tb = el("tbody");
  if (!data.accounts || !data.accounts.length) {
    tb.append(emptyRow(6, "No accounts configured yet. Fill out the form above to add your first account."));
  } else {
    for (const a of data.accounts) {
      const actions = el("td", {});
      const toggle = el("button", { text: a.enabled ? "Disable" : "Enable" });
      toggle.addEventListener("click", async () => {
        try {
          await api(`/admin/api/accounts/${encodeURIComponent(a.label)}`, { method: "PATCH", body: { enabled: !a.enabled } });
          toast(`Account ${a.label} ${a.enabled ? "disabled" : "enabled"}`, "ok");
          route();
        } catch (err) { toast(err.message, "error"); }
      });
      const validate = el("button", { text: "Validate", class: "ghost" });
      validate.addEventListener("click", async () => {
        try {
          const r = await api(`/admin/api/validate?label=${encodeURIComponent(a.label)}`, { method: "POST" });
          toast(`${a.label}: ${r.x_status}`, r.x_status === "CONNECTED" ? "ok" : "error");
          route();
        } catch (err) { toast(err.message, "error"); }
      });
      const del = el("button", { text: "Delete", class: "danger" });
      del.addEventListener("click", async () => {
        if (!confirm(`Delete account '${a.label}'? Stored credentials will be removed.`)) return;
        try {
          await api(`/admin/api/accounts/${encodeURIComponent(a.label)}`, { method: "DELETE" });
          toast(`Account ${a.label} deleted`, "ok");
          route();
        } catch (err) { toast(err.message, "error"); }
      });
      actions.append(toggle, validate, del);
      tb.append(el("tr", {},
        td(a.label, "mono"),
        el("td", {}, el("span", { class: `pill ${a.enabled ? "ok" : "neutral"}`, text: a.enabled ? "ON" : "OFF" })),
        el("td", {}, statusPill(a.status)),
        td(fmtTime(a.last_checked_at)),
        td(a.last_error || "—", "wrap muted"),
        actions));
    }
  }
  t.append(tb);

  const elements = [
    pageTitle("Accounts"),
    el("p", { class: "muted", text: "Credentials are encrypted at rest. Enable/disable and validation apply immediately to every MCP caller." }),
    form
  ];
  if (loadError) {
    elements.push(el("p", { class: "error", role: "alert", text: "Notice: " + (loadError.message || "Could not load existing accounts; you can still add/configure accounts above.") }));
  }
  if (data.warning) {
    elements.push(el("p", { class: "error", role: "alert", text: data.warning }));
  }
  elements.push(t);

  v.replaceChildren(...elements);
};

/* ───────────────────────── tools ───────────────────────── */

views.tools = async (version = renderVersion) => {
  const v = $("#view");
  v.replaceChildren(pageTitle("Tools"), loading("tools"));
  let data;
  try { data = await api("/admin/api/tools"); }
  catch (e) { if (isCurrentRender(version)) showViewError("Tools", e); return; }
  if (!isCurrentRender(version)) return;

  const toolbar = el("div", { class: "toolbar" });
  const search = el("input", { placeholder: "Filter tools by name…", id: "tool-filter", "aria-label": "Filter tools by name", type: "search" });
  const destructiveOnly = el("select", { "aria-label": "Filter by tool kind" },
    el("option", { value: "", text: "All tools" }),
    el("option", { value: "ro", text: "Read-only" }),
    el("option", { value: "de", text: "Destructive" }));
  toolbar.append(search, destructiveOnly);
  const t = table("MCP tools exposed by the gateway");
  t.append(el("thead", {}, el("tr", {},
    th("Tool"), th("Kind"), th("Description"), th("State"), th("Action"))));
  const tb = el("tbody");
  const render = () => {
    tb.innerHTML = "";
    const q = search.value.toLowerCase();
    let shown = 0;
    for (const tool of data.tools) {
      if (q && !tool.name.toLowerCase().includes(q)) continue;
      if (destructiveOnly.value === "ro" && !tool.read_only) continue;
      if (destructiveOnly.value === "de" && !tool.destructive) continue;
      shown += 1;
      const btn = el("button", { text: tool.enabled ? "Disable" : "Enable", class: tool.enabled ? "" : "primary" });
      btn.addEventListener("click", async () => {
        try {
          await api(`/admin/api/tools/${encodeURIComponent(tool.name)}`, { method: "POST", body: { enabled: !tool.enabled } });
          tool.enabled = !tool.enabled;
          toast(`${tool.name} ${tool.enabled ? "enabled" : "disabled"}`, "ok");
          render();
        } catch (err) { toast(err.message, "error"); }
      });
      const kind = tool.destructive
        ? el("span", { class: "pill bad", text: "DESTRUCTIVE" })
        : tool.read_only ? el("span", { class: "pill ok", text: "READ" })
        : el("span", { class: "pill info", text: "WRITE" });
      tb.append(el("tr", { "data-name": tool.name },
        td(tool.name, "mono"),
        el("td", {}, kind),
        td(tool.description || "", "wrap muted"),
        el("td", {}, el("span", { class: `pill ${tool.enabled ? "ok" : "neutral"}`, text: tool.enabled ? "ENABLED" : "DISABLED" })),
        el("td", {}, btn)));
    }
    if (!shown) tb.append(emptyRow(5, "No tools match the current filter."));
  };
  search.addEventListener("input", render);
  destructiveOnly.addEventListener("change", render);
  t.append(tb);
  v.replaceChildren(
    pageTitle(`Tools (${data.count})`),
    toolbar, t,
    el("p", { class: "muted mt", text: "Disabled tools are rejected at call time with a clear error. Destructive tools always require an explicit MCP call — they never run as side effects." }));
  render();
};

/* ───────────────────────── usage ───────────────────────── */

views.usage = async (version = renderVersion) => {
  const v = $("#view");
  v.replaceChildren(pageTitle("Usage logs"), loading("usage logs"));
  let data, tools;
  const state = { offset: 0, tool: "", ok: "" };
  try {
    [data, tools] = await Promise.all([api("/admin/api/usage?limit=50"), api("/admin/api/tools")]);
  } catch (e) { if (isCurrentRender(version)) showViewError("Usage logs", e); return; }
  if (!isCurrentRender(version)) return;

  const toolbar = el("div", { class: "toolbar" });
  const toolSel = el("select", { "aria-label": "Filter by tool" }, el("option", { value: "", text: "All tools" }));
  for (const t of tools.tools) toolSel.append(el("option", { value: t.name, text: t.name }));
  const okSel = el("select", { "aria-label": "Filter by outcome" },
    el("option", { value: "", text: "Any outcome" }),
    el("option", { value: "true", text: "Success only" }),
    el("option", { value: "false", text: "Errors only" }));
  toolSel.addEventListener("change", () => { state.tool = toolSel.value; state.offset = 0; load(); });
  okSel.addEventListener("change", () => { state.ok = okSel.value; state.offset = 0; load(); });
  toolbar.append(toolSel, okSel);

  const t = table("Recorded tool calls");
  t.append(el("thead", {}, el("tr", {},
    th("Time"), th("Tool"), th("Outcome"), th("Duration"), th("Caller"), th("Error"))));
  const tb = el("tbody");
  const pager = el("div", { class: "pager" });
  const prev = el("button", { type: "button" }, svgIcon(ICON_LEFT), el("span", { text: "Newer" }));
  const next = el("button", { type: "button" }, el("span", { text: "Older" }), svgIcon(ICON_RIGHT));
  const info = el("span", {});
  prev.addEventListener("click", () => { state.offset = Math.max(0, state.offset - 50); load(); });
  next.addEventListener("click", () => { if (state.offset + 50 < data.total) { state.offset += 50; load(); } });
  pager.append(prev, next, info);

  async function load() {
    const qs = new URLSearchParams({ limit: "50", offset: String(state.offset) });
    if (state.tool) qs.set("tool", state.tool);
    if (state.ok) qs.set("ok", state.ok);
    try { data = await api(`/admin/api/usage?${qs}`); }
    catch (e) { if (isCurrentRender(version)) toast(e.message, "error"); return; }
    if (!isCurrentRender(version)) return;
    tb.innerHTML = "";
    if (!data.rows.length) tb.append(emptyRow(6, "No usage recorded yet."));
    for (const r of data.rows) {
      tb.append(el("tr", {},
        td(fmtTime(r.ts), "mono"),
        td(r.tool_name, "mono"),
        el("td", {}, el("span", { class: `pill ${r.ok ? "ok" : "bad"}`, text: r.ok ? "OK" : "ERROR" })),
        td(`${r.duration_ms} ms`),
        td(r.caller_fp || "—", "mono muted"),
        td(r.error || "—", "wrap muted")));
    }
    info.textContent = `${data.total} total · showing ${data.offset + 1}–${Math.min(data.offset + data.rows.length, data.total)}`;
    prev.disabled = data.offset === 0;
    next.disabled = data.offset + 50 >= data.total;
  }
  t.append(tb);
  v.replaceChildren(pageTitle("Usage logs"), toolbar, t, pager);
  await load();
};

/* ───────────────────────── tool tester ───────────────────────── */

views.tester = async (version = renderVersion) => {
  const v = $("#view");
  v.replaceChildren(pageTitle("Tool tester"), loading("tools"));
  let tools;
  try { tools = await api("/admin/api/tools"); }
  catch (e) { if (isCurrentRender(version)) showViewError("Tool tester", e); return; }
  if (!isCurrentRender(version)) return;

  const form = el("form", { class: "inline", id: "tester-form" });
  const toolSel = el("select", { id: "t-tool" });
  for (const t of tools.tools) {
    toolSel.append(el("option", {
      value: t.name,
      text: `${t.name}${t.destructive ? " — destructive" : t.read_only ? "" : " — write"}`,
    }));
  }
  const argsBox = el("input", { id: "t-args", placeholder: '{"username":"nasa"}', type: "text" });
  const allowWriteBox = el("input", { id: "t-allow-write", type: "checkbox" });
  const allowWriteLabel = el("label", { for: "t-allow-write", text: "Allow write tools (non-read-only) in this run" });
  const runBtn = el("button", { class: "primary", type: "submit", text: "Run tool" });
  form.append(
    el("div", { class: "row" },
      el("div", { class: "field" },
        el("label", { for: "t-tool", text: "Tool" }), toolSel),
      el("div", { class: "field" },
        el("label", { for: "t-args", text: "Arguments (JSON)" }), argsBox)),
    el("div", { class: "row check-row" }, allowWriteBox, allowWriteLabel),
    el("div", { class: "row" }, runBtn));

  const info = el("p", { class: "muted", text: "Executes in-process through the same middleware as remote calls (flags, hard blocks, usage logging). Read-only tools run by default; write tools need the opt-in checkbox; blocked local-file tools stay blocked." });
  const out = el("pre", { class: "tester-out", "aria-live": "polite", "aria-label": "Tool result" });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    runBtn.disabled = true;
    runBtn.textContent = "Running…";
    out.textContent = "Running…";
    let args = {};
    const raw = argsBox.value.trim();
    if (raw) {
      try { args = JSON.parse(raw); }
      catch (err) { out.textContent = "Invalid JSON arguments: " + err.message; runBtn.disabled = false; runBtn.textContent = "Run tool"; return; }
    }
    try {
      const res = await api(`/admin/api/tools/${encodeURIComponent(toolSel.value)}/test`,
        { method: "POST", body: { arguments: args, allow_non_read_only: allowWriteBox.checked } });
      out.textContent = res.ok ? res.result : `ERROR: ${res.error}`;
    } catch (err) { out.textContent = "ERROR: " + err.message; }
    runBtn.disabled = false;
    runBtn.textContent = "Run tool";
  });

  v.replaceChildren(pageTitle("Tool tester"), form, info, out);
};

/* ───────────────────────── MCP clients ───────────────────────── */

views.clients = async (version = renderVersion) => {
  const v = $("#view");
  v.replaceChildren(pageTitle("MCP clients"), loading("clients"));
  let data;
  try { data = await api("/admin/api/clients"); }
  catch (e) { if (isCurrentRender(version)) showViewError("MCP clients", e); return; }
  if (!isCurrentRender(version)) return;

  const t = table("MCP clients seen by this gateway");
  t.append(el("thead", {}, el("tr", {},
    th("Client"), th("Versions"), th("Handshakes"), th("First seen"), th("Last seen"), th("State"))));
  const tb = el("tbody");
  if (!data.clients.length) tb.append(emptyRow(6, "No MCP handshakes recorded yet."));
  for (const c of data.clients) {
    tb.append(el("tr", {},
      td(c.name, "mono"),
      td(Object.keys(c.versions).join(", "), "mono muted"),
      td(String(c.handshakes)),
      td(fmtTime(c.first_seen)),
      td(fmtTime(c.last_seen)),
      el("td", {}, el("span", { class: `pill ${c.active ? "ok" : "neutral"}`,
        text: c.active ? "ACTIVE" : "IDLE" }))));
  }
  t.append(tb);
  const nodes = [pageTitle(`MCP clients (${data.clients.length})`), t];
  if (data.note) nodes.push(el("p", { class: "muted mt", text: data.note }));
  nodes.push(el("p", { class: "muted mt", text: "Identified from real MCP initialize handshakes — the client name and version come from the protocol, not from a request header, so they cannot be spoofed by a caller." }));
  v.replaceChildren(...nodes);
};

/* ───────────────────────── admin sessions ───────────────────────── */

views.sessions = async (version = renderVersion) => {
  const v = $("#view");
  v.replaceChildren(pageTitle("Admin sessions"), loading("sessions"));
  let data;
  try { data = await api("/admin/api/sessions"); }
  catch (e) { if (isCurrentRender(version)) showViewError("Admin sessions", e); return; }
  if (!isCurrentRender(version)) return;

  const revokeBtn = el("button", { class: "danger", type: "button", text: "Revoke all sessions" });
  revokeBtn.addEventListener("click", async () => {
    if (!confirm("Revoke ALL admin dashboard sessions? You will be signed out everywhere (scripts using the admin bearer token are unaffected).")) return;
    try {
      const r = await api("/admin/api/sessions", { method: "DELETE" });
      toast(`Revoked ${r.revoked} session(s)`, "ok");
      route();
    } catch (err) { toast(err.message, "error"); }
  });

  const t = table("Active admin dashboard sessions");
  t.append(el("thead", {}, el("tr", {},
    th("Source"), th("Session (hash prefix)"), th("Age"), th("Expires in"))));
  const tb = el("tbody");
  if (!data.sessions.length) tb.append(emptyRow(4, "No active admin sessions."));
  for (const s of data.sessions) {
    tb.append(el("tr", {},
      td(s.source),
      td(s.hash_prefix, "mono"),
      td(fmtDuration(s.age_seconds * 1000)),
      td(fmtDuration(s.expires_in_seconds * 1000))));
  }
  t.append(tb);
  v.replaceChildren(
    pageTitle(`Admin sessions (${data.sessions.length})`), t,
    el("div", { class: "mt" }, revokeBtn),
    el("p", { class: "muted mt", text: "Sessions are random server-side tokens (only their hash is stored). Revoking signs out every browser session at once; bearer-token scripts keep working." }));
};

/* ───────────────────────── audit ───────────────────────── */

views.audit = async (version = renderVersion) => {
  const v = $("#view");
  v.replaceChildren(pageTitle("Audit log"), loading("audit log"));
  const state = { offset: 0 };
  let data;
  try { data = await api("/admin/api/audit?limit=50"); }
  catch (e) { if (isCurrentRender(version)) showViewError("Audit log", e); return; }
  if (!isCurrentRender(version)) return;

  const t = table("Admin actions, most recent first");
  t.append(el("thead", {}, el("tr", {},
    th("Time"), th("Action"), th("Detail"), th("Request ID"))));
  const tb = el("tbody");
  const pager = el("div", { class: "pager" });
  const prev = el("button", { type: "button" }, svgIcon(ICON_LEFT), el("span", { text: "Newer" }));
  const next = el("button", { type: "button" }, el("span", { text: "Older" }), svgIcon(ICON_RIGHT));
  const info = el("span", {});
  prev.addEventListener("click", () => { state.offset = Math.max(0, state.offset - 50); load(); });
  next.addEventListener("click", () => { state.offset += 50; load(); });
  pager.append(prev, next, info);

  async function load() {
    try { data = await api(`/admin/api/audit?limit=50&offset=${state.offset}`); }
    catch (e) { if (isCurrentRender(version)) toast(e.message, "error"); return; }
    if (!isCurrentRender(version)) return;
    tb.innerHTML = "";
    if (!data.rows.length) tb.append(emptyRow(4, "No admin actions recorded yet."));
    for (const r of data.rows) {
      tb.append(el("tr", {},
        td(fmtTime(r.ts), "mono"),
        td(r.action, "mono"),
        td(r.detail || "—", "wrap muted"),
        td(r.request_id || "—", "mono muted")));
    }
    info.textContent = `showing ${data.offset + 1}–${data.offset + data.rows.length}`;
    prev.disabled = state.offset === 0;
    next.disabled = data.rows.length < 50;
  }
  t.append(tb);
  v.replaceChildren(
    pageTitle("Audit log"), t, pager,
    el("p", { class: "muted mt", text: "Every admin-panel action (logins, account changes, tool toggles, backups) is recorded here. Secrets are never included." }));
  await load();
};

/* ───────────────────────── backup ───────────────────────── */

views.backup = async (version = renderVersion) => {
  const v = $("#view");
  v.replaceChildren(pageTitle("Backup"), loading("backup state"));
  let d;
  try { d = await api("/admin/api/overview"); }
  catch (e) { if (isCurrentRender(version)) showViewError("Backup", e); return; }
  if (!isCurrentRender(version)) return;
  const b = d.backup;
  const btn = el("button", { class: "primary", type: "button", text: "Run backup now" });
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.textContent = "Running…";
    try {
      const res = await api("/admin/api/backup", { method: "POST" });
      toast(res.ok ? `Backup OK: ${res.accounts} accounts, ${res.tool_flags} flags, ${res.admin_audit} audit rows` : "Backup failed: " + res.error, res.ok ? "ok" : "error");
      views.backup();
    } catch (err) { toast(err.message, "error"); btn.disabled = false; btn.textContent = "Run backup now"; }
  });
  v.replaceChildren(
    pageTitle("Backup"),
    el("div", { class: "cards" },
      card("Status", backupChip(b.ok), b.backend === "none" ? "not configured" : b.backend),
      card("Last run", el("span", { text: fmtTime(b.last_backup_at) }), b.last_backup_error || ""),
      card("Schedule", el("span", { text: `every ${b.interval_hours}h` }), "plus on-demand"),
      card("Snapshots", el("span", { text: String((b.snapshots || []).length) }),
        b.restored_from_snapshot
          ? `serving from snapshot ${fmtTime(b.restored_from_snapshot)}`
          : `kept ${b.retention_days}d`)),
    el("div", { class: "mt" }, btn),
    el("p", { class: "muted mt", text: "Every run appends a new snapshot — accounts (encrypted), schema_migrations, tool flags and the audit log — to the secondary database; earlier snapshots are never overwritten. Snapshots older than the retention window are pruned automatically. Usage logs stay on the primary with time-based pruning." }),
    snapshotTable(b));

  /* One row per snapshot, newest first. Restoring writes a snapshot BACK into
     the primary store, the only path that does so: the automatic fallback
     only re-hydrates the local Spectre pool, so resurrecting a deleted
     account or repairing a corrupt credential row stays deliberate. */
  function snapshotTable(backup) {
    const rows = backup.snapshots || [];
    const t = table("Backup snapshots");
    t.append(el("thead", {}, el("tr", {},
      th("Snapshot (UTC)"), th("Triggered by"), th("Accounts"), th("Migrations"),
      th("Flags"), th("Audit rows"), th(""))));
    const tb = el("tbody");
    if (!rows.length) tb.append(emptyRow(7, "No snapshot yet — run a backup."));
    for (const s of rows) {
      const restore = el("button", { type: "button", class: "ghost", text: "Restore" });
      restore.addEventListener("click", async () => {
        if (!confirm(`Restore snapshot ${s.snapshot_at} back into the primary database? Accounts present in the snapshot are written back; accounts that exist only on the primary are left alone.`)) return;
        restore.disabled = true;
        restore.textContent = "Restoring…";
        try {
          const res = await api("/admin/api/backup/restore", {
            method: "POST", body: { snapshot_at: s.snapshot_at } });
          toast(`Restored ${res.accounts} account(s), ${res.tool_flags} flag(s), `
            + `${res.admin_audit} audit row(s) from ${fmtTime(res.snapshot_at)}`, "ok");
          views.backup();
        } catch (err) { toast(err.message, "error"); restore.disabled = false; restore.textContent = "Restore"; }
      });
      tb.append(el("tr", {},
        td(s.snapshot_at, "mono"),
        td(s.triggered_by || "—"),
        td(String(s.account_rows)),
        td(String(s.migration_rows)),
        td(String(s.tool_flag_rows)),
        td(String(s.audit_rows)),
        el("td", {}, restore)));
    }
    t.append(tb);
    return el("div", { class: "mt" }, t);
  }
};

/* ───────────────────────── go ───────────────────────── */

boot();
