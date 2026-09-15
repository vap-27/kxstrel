"use strict";
/* Test harness for the theme section of app/static/app.js.

   The repo is browserless by design, so nothing here drives a browser: Node's
   own `vm` evaluates the shipped theme section against hand-written stubs for
   the few globals it touches (window.matchMedia, localStorage, the document
   element and the two theme controls). No DOM library, no dependency, no
   network — the assertions live in tests/test_admin_design.py, which feeds the
   section in as a file argument and reads the JSON this prints.

   Usage: node tests/theme_harness.js <theme-section.js>

   Output: {"scenarios": {"<name>": [{"label", "dataTheme", "resolved",
   "pressed", "writes", "error"}, ...]}, "media": {...}}
   `error` is only set when the module *threw* while loading or handling an
   event: "does not throw" is a behaviour under test, so it is recorded rather
   than crashing the harness. */

const fs = require("fs");
const vm = require("vm");

const SOURCE = fs.readFileSync(process.argv[2], "utf8");

/* A real element's `dataset` IS its data-* attributes (setAttribute, removeAttribute
   and the property view are three faces of one store), so the fakes below must
   share that store or the assertions would be fiction. */
function camelToData(prop) {
  return "data-" + prop.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase());
}

function datasetOf(attrs) {
  return new Proxy({}, {
    get: (_t, prop) => (typeof prop === "string" ? attrs[camelToData(prop)] : undefined),
    set: (_t, prop, value) => { attrs[camelToData(prop)] = String(value); return true; },
    has: (_t, prop) => camelToData(prop) in attrs,
  });
}

function element(attrs, listeners) {
  return {
    attrs,
    listeners,
    dataset: datasetOf(attrs),
    setAttribute(name, value) { attrs[name] = String(value); },
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(attrs, name) ? attrs[name] : null;
    },
    hasAttribute(name) { return Object.prototype.hasOwnProperty.call(attrs, name); },
    removeAttribute(name) { delete attrs[name]; },
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
  };
}

const CHOICES = ["system", "light", "dark"];

/* matchMedia shapes a real engine can present: the modern one, the legacy one
   (addListener), one with no subscription API at all, something unusable, and
   two failure modes — an engine without window.matchMedia at all, and one
   where the call itself throws. */
function mediaQueryFactory(kind, state) {
  const created = [];
  const make = () => {
    const query = { handlers: [] };
    Object.defineProperty(query, "matches", { get: () => state.osDark });
    if (kind === "modern" || kind === "legacy") {
      query.addEventListener = (type, fn) => { query.handlers.push(fn); };
    }
    if (kind === "legacy") {
      delete query.addEventListener;
      query.addListener = (type, fn) => { query.handlers.push(fn); };
    }
    created.push(query);
    return query;
  };
  const matchMedia = () => {
    if (kind === "throws") throw new Error("matchMedia blocked by policy");
    if (kind === "unusable") return {};
    return make();
  };
  return { matchMedia, created, kind };
}

function environment(options) {
  const opts = Object.assign({ stored: null, osDark: false, kind: "modern", storageThrows: false }, options);
  const state = { osDark: opts.osDark };
  const writes = [];
  let stored = opts.stored;

  const rootAttrs = {};
  const root = element(rootAttrs, {});
  /* Two groups of three, like the page: the sign-in card and the sidebar. */
  const groups = [0, 1].map(() => CHOICES.map((choice) => {
    const button = element({ "aria-pressed": "false" }, {});
    button.dataset.themeChoice = choice;
    return button;
  }));
  const buttons = groups.flat();

  const documentElement = {
    documentElement: root,
    querySelectorAll(selector) {
      return selector === ".theme-toggle [data-theme-choice]" ? buttons : [];
    },
  };

  const storage = {
    getItem() {
      if (opts.storageThrows) throw new Error("storage blocked (private mode)");
      return stored;
    },
    setItem(key, value) {
      if (opts.storageThrows) throw new Error("storage blocked (private mode)");
      writes.push([key, String(value)]);
      stored = String(value);
    },
  };

  const media = mediaQueryFactory(opts.kind, state);
  const win = opts.kind === "missing" ? {} : { matchMedia: media.matchMedia };

  const env = {
    options: opts,
    root,
    rootAttrs,
    groups,
    buttons,
    writes,
    media,
    get stored() { return stored; },
    setOsDark(value) { state.osDark = value; },
    /* Deliver a change event to every subscription the module opened. */
    fire() {
      for (const query of media.created) {
        for (const handler of query.handlers) handler({ matches: state.osDark, media: "(prefers-color-scheme: dark)" });
      }
    },
    click(choice, group = 0) {
      const button = groups[group].find((b) => b.dataset.themeChoice === choice);
      for (const handler of button.listeners.click || []) handler({ type: "click" });
    },
    snapshot(label) {
      return {
        label,
        dataTheme: root.attrs["data-theme"] ?? null,
        resolved: root.attrs["data-theme-resolved"] ?? null,
        pressed: Object.fromEntries(buttons.map((b, i) => [`${Math.floor(i / 3)}:${b.dataset.themeChoice}`, b.attrs["aria-pressed"] ?? null])),
        writes: writes.map(([key, value]) => `${key}=${value}`),
        /* Handlers the module managed to subscribe: >0 means it is listening
           for OS flips, 0 means it is not (and may not throw about it). */
        subscriptions: media.created.reduce((total, query) => total + query.handlers.length, 0),
      };
    },
  };
  env.sandbox = { window: win, document: documentElement, localStorage: storage };
  return env;
}

/* The module keeps its mode in a closure; this is the only handle the harness
   needs on it, exported on the context's global. */
const EXPORT = `
;globalThis.__theme = {
  applyTheme, resolveTheme, systemTheme, storedTheme, currentMode, normalizeMode, persistTheme,
  get mode() { return themeMode; },
};`;

function load(options) {
  const env = environment(options);
  const context = vm.createContext(env.sandbox);
  try {
    vm.runInContext(SOURCE + EXPORT, context, { filename: "theme-section.js" });
  } catch (error) {
    env.loadError = String(error && error.message);
  }
  env.theme = env.sandbox.__theme;
  return env;
}

/* Every scenario: load the shipped section, drive it, snapshot after each
   step. An exception anywhere is recorded on the snapshot, never thrown, so a
   "must not throw" contract can be asserted rather than crashing the run. */
const scenarios = {};

function scenario(name, options, steps) {
  const env = load(options);
  const shots = [];
  const step = (label, fn) => {
    try {
      if (fn) fn(env);
      shots.push(Object.assign(env.snapshot(label), { error: null }));
    } catch (error) {
      shots.push(Object.assign(env.snapshot(label), { error: String(error && error.message) }));
    }
  };
  step(env.loadError ? `load failed: ${env.loadError}` : "load");
  if (!env.loadError) steps(step, env);
  scenarios[name] = shots;
}

/* ── default: nothing stored means system, and system follows the OS ────── */
scenario("default_nothing_stored_os_light", { osDark: false }, (step) => {
  step("os flips to dark", (env) => { env.setOsDark(true); env.fire(); });
  step("os flips back to light", (env) => { env.setOsDark(false); env.fire(); });
});

scenario("default_nothing_stored_os_dark", { osDark: true }, (step) => {
  step("os flips to light", (env) => { env.setOsDark(false); env.fire(); });
});

/* ── explicit choices pin the theme and stop following the OS ───────────── */
scenario("explicit_light_beats_os_dark", { stored: "light", osDark: false }, (step) => {
  step("os flips to dark", (env) => { env.setOsDark(true); env.fire(); });
});

scenario("explicit_dark_beats_os_light", { stored: "dark", osDark: true }, (step) => {
  step("os flips to light", (env) => { env.setOsDark(false); env.fire(); });
});

/* ── clicking: explicit choice, then back to system ─────────────────────── */
scenario("click_light_then_system_then_dark", { osDark: true }, (step) => {
  step("click Light (os dark)", (env) => env.click("light"));
  step("os flips to light (still pinned)", (env) => { env.setOsDark(false); env.fire(); });
  step("click System (os light)", (env) => env.click("system"));
  step("os flips to dark (following again)", (env) => { env.setOsDark(true); env.fire(); });
  step("click Dark", (env) => env.click("dark"));
  step("os flips to light (pinned again)", (env) => { env.setOsDark(false); env.fire(); });
});

scenario("second_group_is_wired_and_kept_in_sync", { osDark: false }, (step) => {
  step("click Dark in the sidebar group", (env) => env.click("dark", 1));
  step("click System in the sign-in group", (env) => env.click("system", 0));
});

/* ── storage: unreadable, unwritable, or holding junk ───────────────────── */
scenario("stored_junk_reads_as_system", { stored: "banana", osDark: true }, (step) => {
  step("os flips to light", (env) => { env.setOsDark(false); env.fire(); });
});

scenario("storage_throws_everywhere", { storageThrows: true, osDark: true }, (step) => {
  step("click Light", (env) => env.click("light"));
  step("os flips to light", (env) => { env.setOsDark(false); env.fire(); });
  step("click System", (env) => env.click("system"));
});

/* ── matchMedia: legacy, absent, broken, useless ────────────────────────── */
scenario("legacy_add_listener", { kind: "legacy", osDark: false }, (step) => {
  step("os flips to dark", (env) => { env.setOsDark(true); env.fire(); });
});

scenario("no_listener_api", { kind: "listenerless", osDark: true }, (step) => {
  step("os flips to light", (env) => { env.setOsDark(false); env.fire(); });
});

scenario("matchmedia_missing", { kind: "missing" }, (step) => {
  step("nothing to follow", () => {});
});

scenario("matchmedia_throws", { kind: "throws" }, (step) => {
  step("nothing to follow", () => {});
});

scenario("matchmedia_unusable", { kind: "unusable" }, (step) => {
  step("nothing to follow", () => {});
});

process.stdout.write(JSON.stringify({ scenarios }, null, 1));
