// byn portal — vanilla SPA. No login: structure + (unlocked) names/values
// mirror the CLI/TUI. Values need the target vault unlocked, toggled
// per-vault from the tree. No framework.
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, cls, txt) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (txt != null) n.textContent = txt;
  return n;
};
const enc = encodeURIComponent;

// ---- inline SVG icons (static paths) ----
const SVGNS = "http://www.w3.org/2000/svg";
const ICONS = {
  eye:    "M1 8s2.6-5 7-5 7 5 7 5-2.6 5-7 5-7-5-7-5z|M8 5.4a2.6 2.6 0 100 5.2 2.6 2.6 0 000-5.2z",
  copy:   "M6 6h7v7H6z|M3.2 10.2V3.2H10",
  pencil: "M11.5 2.2l2.3 2.3-8.1 8.1L3 13.3l.7-2.7 7.8-8.4z",
  trash:  "M3 4.4h10|M6 4.4V3h4v1.4|M4.5 4.4l.6 9h5.8l.6-9",
  lock:   "M3.6 7.4h8.8v6H3.6z|M5.6 7.4V5a2.4 2.4 0 014.8 0v2.4",
  unlock: "M3.6 7.4h8.8v6H3.6z|M5.6 7.4V5a2.4 2.4 0 014.7-.6",
  key:    "M10 3a3 3 0 102.6 4.5L14 9l-1 1 1 1-1.5 1.5L11 11l-1 1-1.4-1.4A3 3 0 0010 3z|M9.4 6.6h.01",
  // revert: a counter-clockwise "undo" arrow — head on the left, tail curving
  // down-right. Used to drop an env's override back to the inherited default.
  revert:  "M6.5 3.5 4 6l2.5 2.5|M4 6h5a4 4 0 014 4v.6",
  // persist: a down-arrow landing on a baseline — "push this value down into
  // the default env" (echoes the ↓ inherit badge). Promotes a value to default.
  persist: "M8 3v6.2|M5.6 6.8 8 9.2l2.4-2.4|M4 12h8",
};
function icon(name) {
  const svg = document.createElementNS(SVGNS, "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("class", "ico");
  for (const d of ICONS[name].split("|")) {
    const p = document.createElementNS(SVGNS, "path");
    p.setAttribute("d", d);
    svg.appendChild(p);
  }
  return svg;
}
function iconBtn(name, cls, title, fn) {
  const b = el("button", "act-ico " + (cls || ""));
  b.title = title; b.appendChild(icon(name)); b.onclick = fn;
  return b;
}
function autoGrow(ta) { ta.style.height = "auto"; ta.style.height = Math.min(ta.scrollHeight, 200) + "px"; }

// Scope name rules, mirrored from the daemon (`^[a-z0-9][a-z0-9_-]{0,62}$`).
const SCOPE_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,62}$/;
function validateScopeName(v) {
  if (!v) return "name is required";
  if (/[A-Z]/.test(v)) return "lowercase only — try “" + v.toLowerCase() + "”";
  if (!SCOPE_NAME_RE.test(v)) return "use a–z, 0–9, - or _ · 1–63 chars · no leading - or _";
  return null;
}

const state = {
  scope: { vault: "", project: "", env: "" },
  view: "entries", // "entries" | "projects" | "envs"
  open: { vaults: new Set(), projects: new Set() },
  vaults: [],
  entries: [], defaultNames: new Set(), filter: "",
  revealTimers: {},
  revealCells: {},  // name → value cell <span>, for reveal-all in the entries view
};

// Armed for ~700ms after pressing `l`, so the `l a` chord can lock all vaults.
let lockChordArmed = false;

// ---- history-API router -------------------------------------------------
//
// Route table:
//   /                             → entries, default scope (first vault/default/default)
//   /entries/<vault>              → project-browse for vault
//   /entries/<vault>/<proj>       → env-browse for vault/project
//   /entries/<vault>/<proj>/<env> → entries at that scope
//   /trust                        → trust list
//   /audit                        → audit view
//   /settings                     → settings panel
//   /studio                       → studio create mode
//   /studio?path=<urlencoded>     → studio edit mode (loads the file)
//   <anything else>               → entries, replaceState("/")
//
// navigate(path) is the single call-site for all programmatic navigation.
// Every nav action (tree clicks, nav buttons, trust-row edit, etc.) calls
// navigate(), which calls pushState and then renders the new view.
//
// popstate fires on browser back/forward; it calls renderFromLocation() to
// render the view described by the current URL without pushing a new entry.
//
// initial boot calls renderFromLocation() once to deep-link the initial page.
//
// pushState vs replaceState:
//   - Explicit user nav (clicking a vault/project/env in the tree, pressing
//     trust/audit/settings/studio buttons, breadcrumb clicks) → pushState so
//     back/forward work as expected.
//   - Scope changes already in the entries view (selectScope from the tree
//     when view is already "entries") → pushState (each scope selection IS
//     a distinct browsing event the user wants to be able to go back to).
//   - Unknown/unrecognised paths on initial load → replaceState("/") so the
//     garbage URL is replaced in history, not added.

// ---- dirty-editor navigation guard -------------------------------------
//
// studioBaseline holds the serialized content that was last saved (or the
// initial default for new files). It is set when the studio opens and after
// every successful save; Reset-to-baseline also resets it.
// cfgBaseline is the analogue for the settings panel.
//
// isDirtyStudio / isDirtyCfg do a cheap string compare — they do NOT run on
// every keystroke, only when a navigation is about to happen.
//
// Tab-close / beforeunload protection is explicitly out of scope: the owner
// wants byn modals only, and beforeunload requires browser-native confirms.

let studioBaseline = null; // null = studio not open
let cfgBaseline    = null; // null = settings not open

function isDirtyStudio() {
  if (!studioState || studioBaseline === null) return false;
  return currentContent() !== studioBaseline;
}

function isDirtyCfg() {
  if (!cfgState || cfgBaseline === null) return false;
  const cur = cfgState.rawMode ? (cfgState.rawContent || "") : serializeCfg(cfgState);
  return cur !== cfgBaseline;
}

// studioFileLabel returns a short label for the dirty-nav dialog body.
function studioFileLabel() {
  if (studioState && studioState.filePath) return studioState.filePath;
  return "new .byn";
}

// guardDirtyNav checks whether the studio or settings editor is dirty. If
// dirty it shows a byn modal. Calls proceed() when the user chooses Discard
// or when neither editor is dirty. Does NOT proceed on Stay or dismiss.
//
// For popstate navigation we also need to re-push the current URL so the
// browser history entry is restored (undoing the back/forward press).
// Callers that need this pass repushURL.
async function guardDirtyNav(proceed, repushURL) {
  const dirtyStudio = isDirtyStudio();
  const dirtyCfg    = isDirtyCfg();

  if (!dirtyStudio && !dirtyCfg) { await proceed(); return; }

  let title, body;
  if (dirtyStudio) {
    title = "Discard unsaved changes?";
    body  = "You have unsaved edits in the .byn studio (" + studioFileLabel() + "). They will be lost.";
  } else {
    title = "Discard unsaved changes?";
    body  = "You have unsaved edits in the settings panel. They will be lost.";
  }

  const ok = await openDialog({
    title,
    message: body,
    okText:  "discard",
    danger:  true,
  });

  if (ok) {
    // User chose Discard — clear baselines so the guard does not fire again
    // while the navigation completes and tears down the view.
    studioBaseline = null;
    cfgBaseline    = null;
    await proceed();
  } else {
    // User chose Stay — if this was a popstate event, re-push the old URL so
    // the history entry is restored (the browser already moved; we undo it).
    if (repushURL) history.pushState(null, "", repushURL);
  }
}

function navigate(path) {
  history.pushState(null, "", path);
  renderFromLocation();
}

// navigateGuarded wraps navigate() with the dirty-editor guard.
async function navigateGuarded(path) {
  await guardDirtyNav(() => navigate(path));
}

function replaceNav(path) {
  history.replaceState(null, "", path);
}

// locationToRoute parses window.location and returns { view, scope, studioPath }.
// scope = { vault, project, env } for the entries view; empty otherwise.
// studioPath = the ?path= param for studio edit mode, or "".
function locationToRoute() {
  const p = decodeURIComponent(window.location.pathname);
  const q = new URLSearchParams(window.location.search);

  if (p === "/" || p === "") {
    return { view: "entries", scope: null, studioPath: "" };
  }
  if (p === "/trust") {
    return { view: "trust", scope: null, studioPath: "" };
  }
  if (p === "/audit") {
    return { view: "audit", scope: null, studioPath: "" };
  }
  if (p === "/settings") {
    return { view: "settings", scope: null, studioPath: "" };
  }
  if (p === "/studio") {
    const studioPath = q.get("path") || "";
    return { view: "studio", scope: null, studioPath };
  }
  // /entries/<vault>/<project>/<env>
  const m = p.match(/^\/entries\/([^/]+)\/([^/]+)\/([^/]+)$/);
  if (m) {
    return {
      view: "entries",
      scope: {
        vault:   decodeURIComponent(m[1]),
        project: decodeURIComponent(m[2]),
        env:     decodeURIComponent(m[3]),
      },
      studioPath: "",
    };
  }
  // /entries/<vault>/<project>  → env-browse
  const m2 = p.match(/^\/entries\/([^/]+)\/([^/]+)$/);
  if (m2) {
    return {
      view: "envs",
      scope: { vault: decodeURIComponent(m2[1]), project: decodeURIComponent(m2[2]), env: "" },
      studioPath: "",
    };
  }
  // /entries/<vault>  → project-browse
  const m1 = p.match(/^\/entries\/([^/]+)$/);
  if (m1) {
    return {
      view: "projects",
      scope: { vault: decodeURIComponent(m1[1]), project: "", env: "" },
      studioPath: "",
    };
  }
  // Unknown path → fall back to entries root.
  return { view: "entries", scope: null, studioPath: "", unknown: true };
}

// entriesPath builds the /entries/<v>/<p>/<e> URL for a scope.
function entriesPath(vault, project, env) {
  return "/entries/" + enc(vault) + "/" + enc(project) + "/" + enc(env);
}
// vaultPath builds the /entries/<v> URL for a vault project-browse.
function vaultPath(vault) { return "/entries/" + enc(vault); }
// projectPath builds the /entries/<v>/<p> URL for an env-browse.
function projectPath(vault, project) { return "/entries/" + enc(vault) + "/" + enc(project); }

// renderFromLocation reads window.location, updates state, and renders.
// Called on boot and on popstate (back/forward navigation).
async function renderFromLocation() {
  const route = locationToRoute();
  if (route.unknown) {
    replaceNav("/");
  }
  if (route.view === "studio") {
    // Deep-link into studio. State sync: close any existing studio state.
    studioState = null;
    state.view = "studio";
    await renderTree();
    openBynStudio({ mode: route.studioPath ? "edit" : "create", path: route.studioPath || undefined });
    return;
  }
  if (route.view === "trust") {
    state.view = "trust";
    await renderTree();
    renderContent();
    return;
  }
  if (route.view === "audit") {
    if (!state.scope.vault) {
      // Audit needs a vault — redirect to root.
      replaceNav("/");
      state.view = "entries";
      await renderTree();
      renderContent();
      return;
    }
    state.view = "audit";
    await renderTree();
    renderContent();
    return;
  }
  if (route.view === "settings") {
    state.view = "settings";
    await renderTree();
    renderContent();
    return;
  }
  // Projects-browse deep-link (/entries/<vault>).
  if (route.view === "projects" && route.scope) {
    const { vault } = route.scope;
    state.scope = { vault, project: "", env: "" };
    state.view = "projects";
    state.open.vaults.add(vault);
    await renderTree();
    renderContent();
    return;
  }
  // Envs-browse deep-link (/entries/<vault>/<project>).
  if (route.view === "envs" && route.scope) {
    const { vault, project } = route.scope;
    state.scope = { vault, project, env: "" };
    state.view = "envs";
    state.open.vaults.add(vault);
    state.open.projects.add(vault + "/" + project);
    await renderTree();
    renderContent();
    return;
  }
  // Entries view (default or scoped).
  if (route.scope) {
    const { vault, project, env } = route.scope;
    state.scope = { vault, project, env };
    state.view = "entries";
    state.open.vaults.add(vault);
    state.open.projects.add(vault + "/" + project);
    await renderTree();
    await loadEntries();
  } else {
    // Root "/" — renderTree to populate state.vaults, then pick first vault.
    await renderTree();
    if (state.vaults.length) {
      const first = state.vaults[0].name;
      state.scope = { vault: first, project: "default", env: "default" };
      state.open.vaults.add(first);
      state.open.projects.add(first + "/default");
      // Re-render tree to show the vault open, then load entries.
      await renderTree();
      await loadEntries();
    } else {
      state.view = "entries";
      renderContent();
    }
  }
}

// ---- portal owner-token -------------------------------------------------
//
// The portal API is gated by an owner-token (X-Byn-Portal-Token). The token
// is placed in the URL as ?auth=<bootstrap-token> by `byn web`. On first load
// the SPA calls POST /api/session/bootstrap with the one-time bootstrap token
// to receive the persistent portal token, stores the persistent token in
// localStorage, and strips ?auth= from the URL via replaceState — so the
// persistent token never appears in browser history or server logs.
// A ps-captured bootstrap token is single-use and expires in 30s.
//
// If no token is in localStorage and an API call returns 401
// {error:"portal_token_required"}, the SPA renders a full-screen notice
// instead of silently failing.

const PORTAL_TOKEN_KEY = "byn.portal_token";

function portalToken() {
  return localStorage.getItem(PORTAL_TOKEN_KEY) || "";
}

// bootExtractToken runs once at page load. If ?auth= is present in the URL
// it treats the value as a one-time bootstrap token, exchanges it at
// POST /api/session/bootstrap for the persistent portal token, stores that
// in localStorage, and strips ?auth= via replaceState.
//
// Returns a promise that resolves when the exchange is complete (or is a
// no-op when ?auth= is absent). boot() awaits this before making any
// authenticated API calls.
async function bootExtractToken() {
  const url = new URL(window.location.href);
  const bootstrapTok = url.searchParams.get("auth");
  if (!bootstrapTok) return; // nothing to do

  // Strip ?auth= immediately so the bootstrap token is not in history even if
  // the exchange fails.
  url.searchParams.delete("auth");
  window.history.replaceState(null, "", url.pathname + (url.search || "") + url.hash);

  // Exchange the one-time bootstrap token for the persistent portal token.
  // /api/session/bootstrap is ungated (no X-Byn-Portal-Token required) but
  // is sameOrigin-gated on the server side.
  try {
    const res = await fetch("/api/session/bootstrap", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: bootstrapTok }),
    });
    if (res.ok) {
      const data = await res.json();
      if (data && data.portal_token) {
        localStorage.setItem(PORTAL_TOKEN_KEY, data.portal_token);
      }
    }
    // If the exchange fails (expired/replayed token, daemon restart) the user
    // will see the "not authorized" notice on the next API call and can
    // re-run `byn web` to get a fresh session.
  } catch (_) { /* network error — leave localStorage unchanged */ }
}

// ---- theme management ---------------------------------------------------
//
// Three-state: "dark" | "light" | "system".
// Persisted in localStorage("byn.theme"). Defaults to "system".
// "system" tracks matchMedia("(prefers-color-scheme: light)") live.
// The <html data-theme> attribute drives all CSS variable overrides.
//
// A tiny inline script in <head> applies the initial theme before first paint
// (see index.html) to prevent FOUC. This module wires up the three-button
// switcher in the topbar and keeps the system listener in sync.

let _themeMediaQuery = null;
const THEME_KEY = "byn.theme";

function _applyTheme(pref) {
  // pref = "dark" | "light" | "system"
  const html = document.documentElement;
  if (pref === "light" || pref === "dark") {
    html.setAttribute("data-theme", pref);
  } else {
    // system: follow matchMedia
    const m = window.matchMedia("(prefers-color-scheme: light)");
    html.setAttribute("data-theme", m.matches ? "light" : "dark");
  }
}

// _buildThemeIcon returns a <svg> element for the given theme key built
// entirely with createElementNS — no innerHTML, no user data interpolated.
// All shapes use stroke="currentColor" so they inherit the button's colour
// in both light and dark modes. viewBox 0 0 16 16, stroke-width 1.3.
function _buildThemeIcon(key) {
  function svgEl(tag, attrs) {
    const n = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    return n;
  }
  const BASE = { fill: "none", stroke: "currentColor", "stroke-width": "1.3" };
  const ROUND = { ...BASE, "stroke-linecap": "round", "stroke-linejoin": "round" };

  const svg = svgEl("svg", { viewBox: "0 0 16 16", class: "theme-ico",
    "aria-hidden": "true", focusable: "false" });

  if (key === "dark") {
    // Crescent moon (Feather-style, scaled to the 16px viewBox) —
    // visually verified at small sizes; a hand-rolled arc path here
    // previously rendered as a lumpy blob.
    svg.appendChild(svgEl("path", { ...ROUND,
      d: "M14 8.53A6 6 0 1 1 7.47 2 4.67 4.67 0 0 0 14 8.53z" }));

  } else if (key === "light") {
    // Sun: small circle centre + 8 short ray stubs.
    svg.appendChild(svgEl("circle", { ...BASE, cx: "8", cy: "8", r: "3" }));
    const rays = [
      "M8 1v2", "M8 13v2", "M1 8h2", "M13 8h2",
      "M3.22 3.22l1.41 1.41", "M11.37 11.37l1.41 1.41",
      "M3.22 12.78l1.41-1.41", "M11.37 4.63l1.41-1.41",
    ];
    for (const d of rays) svg.appendChild(svgEl("path", { ...ROUND, d }));

  } else {
    // Monitor / system: screen rectangle + stand stem + base.
    svg.appendChild(svgEl("rect", { ...ROUND,
      x: "1.5", y: "2.5", width: "13", height: "9", rx: "1.5" }));
    svg.appendChild(svgEl("path", { ...ROUND, d: "M5.5 14.5h5M8 11.5v3" }));
  }
  return svg;
}

// _injectThemeIcons stamps an SVG icon into each theme button using safe
// DOM methods (createElementNS). Called once from wire() when the DOM is ready.
function _injectThemeIcons() {
  const map = { "theme-dark": "dark", "theme-light": "light", "theme-system": "system" };
  for (const [id, key] of Object.entries(map)) {
    const btn = document.getElementById(id);
    if (btn && !btn.querySelector(".theme-ico")) btn.appendChild(_buildThemeIcon(key));
  }
}

function _syncThemeBtns(pref) {
  const ids = ["theme-dark", "theme-light", "theme-system"];
  const prefs = ["dark", "light", "system"];
  ids.forEach((id, i) => {
    const btn = document.getElementById(id);
    if (!btn) return;
    const active = prefs[i] === pref;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-pressed", active ? "true" : "false");
  });
}

function setTheme(pref) {
  localStorage.setItem(THEME_KEY, pref);
  _applyTheme(pref);
  _syncThemeBtns(pref);
  // Start or stop the system media-query listener as needed.
  if (pref === "system") {
    if (!_themeMediaQuery) {
      _themeMediaQuery = window.matchMedia("(prefers-color-scheme: light)");
      _themeMediaQuery.addEventListener("change", _onSystemThemeChange);
    }
  } else {
    if (_themeMediaQuery) {
      _themeMediaQuery.removeEventListener("change", _onSystemThemeChange);
      _themeMediaQuery = null;
    }
  }
}

function _onSystemThemeChange(e) {
  // Only fires when pref is "system" (listener is removed otherwise).
  document.documentElement.setAttribute("data-theme", e.matches ? "light" : "dark");
}

function initTheme() {
  const pref = localStorage.getItem(THEME_KEY) || "system";
  _applyTheme(pref);
  _syncThemeBtns(pref);
  // Wire system listener if needed.
  if (pref === "system") {
    _themeMediaQuery = window.matchMedia("(prefers-color-scheme: light)");
    _themeMediaQuery.addEventListener("change", _onSystemThemeChange);
  }
}

// showUnauthorizedNotice renders a full-screen message when the portal token
// is missing or wrong — i.e., when the browser is not an authorized session.
function showUnauthorizedNotice() {
  // Avoid duplicate notices.
  if (document.getElementById("byn-unauth")) return;
  const notice = document.createElement("div");
  notice.id = "byn-unauth";
  notice.style.cssText = [
    "position:fixed", "inset:0", "display:flex", "flex-direction:column",
    "align-items:center", "justify-content:center",
    "background:var(--unauth-bg)", "color:var(--unauth-fg)",
    "font-family:monospace", "z-index:9999", "padding:2rem", "text-align:center",
  ].join(";");
  const h = document.createElement("h2");
  h.textContent = "This browser isn’t authorized";
  h.style.cssText = "margin:0 0 1rem;font-size:1.25rem;font-weight:600";
  const p = document.createElement("p");
  p.style.cssText = "margin:0;line-height:1.6;max-width:36rem";
  p.textContent = "Run ‘byn web’ from a terminal to open an authorized session. " +
    "The authorization token is stored in localStorage and is valid for this browser profile.";
  const cmd = document.createElement("pre");
  cmd.style.cssText = "margin:1.5rem 0 0;padding:.75rem 1.25rem;border-radius:6px;" +
    "background:var(--unauth-pre-bg);font-size:1rem";
  cmd.textContent = "byn web";
  notice.appendChild(h);
  notice.appendChild(p);
  notice.appendChild(cmd);
  document.body.appendChild(notice);
}

// ---- API ----------------------------------------------------------------

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  // Attach the portal owner-token on every API request. The header is
  // checked server-side against $BYN_DIR/portal.token (mode 0600).
  const tok = portalToken();
  if (tok) opts.headers["X-Byn-Portal-Token"] = tok;
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch (_) {}
  if (!res.ok) {
    // portal_token_required: the browser is not authorized. Show the notice
    // instead of a generic error — the user needs to run `byn web`.
    if (res.status === 401 && data && data.error === "portal_token_required") {
      showUnauthorizedNotice();
      // Throw a sentinel so callers know not to retry with auth-step-up logic.
      const err = new Error("portal_token_required");
      err.status = 401;
      err.code = "portal_token_required";
      throw err;
    }
    const err = new Error((data && data.error) || `${res.status} ${res.statusText}`);
    err.status = res.status;            // 423 ⇒ vault locked
    err.code = data && data.code;       // daemon error code, e.g. "locked"
    throw err;
  }
  return data;
}

// ---- action step-up -------------------------------------------------------

// authorizeStepUp shows an authorization step-up for an action that requires
// fresh credentials (session expired or absent). Passkey-first (mirrors the
// trust-grant flow); falls back to the password dialog. Returns
// { password, presence_token } with exactly one of them set, or null when
// the user cancels.
//
// The returned credential is SINGLE-USE: do not store it; pass it directly
// into the retried request body and discard it after.
async function authorizeStepUp(vault) {
  // Try passkey first — same pattern as tryPasskeyPresence for trust grants.
  const token = await tryPasskeyPresence(vault);
  if (token) return { presence_token: token, password: "" };

  // Fall back to the master-password dialog.
  const r = await openDialog({
    title: "Authorize action",
    okText: "authorize",
    message:
      "Authorization required — enter the master password to authorize this action.",
    fields: [
      { key: "password", label: "master password", type: "password",
        validate: (v) => (v ? null : "password required") },
    ],
  });
  if (!r) return null;
  const pw = r.password;
  // Clear the stored reference after extracting the value so it does not
  // linger in a closure or variable past this call.
  r.password = "";
  return { password: pw, presence_token: null };
}

// apiWithAuth wraps api() and handles auth_required transparently: on first
// auth_required it shows the step-up (passkey or password), merges the
// credential into the request body, and retries exactly once. A second
// auth_required (wrong password, expired token) falls through to the caller
// as a normal error. vault is the vault name for the presence-token scope
// check (used by tryPasskeyPresence).
async function apiWithAuth(method, path, body, vault) {
  try {
    return await api(method, path, body);
  } catch (e) {
    if (e.code !== "auth_required") throw e;
    // First auth_required: ask for credentials.
    const creds = await authorizeStepUp(vault || state.scope.vault);
    if (!creds) throw e; // user cancelled — propagate the original error
    // Merge creds into a fresh body copy (never mutate the original).
    const retryBody = Object.assign({}, body, {
      password: creds.password || "",
      presence_token: creds.presence_token || undefined,
    });
    // Single retry — any further auth_required propagates normally.
    return await api(method, path, retryBody);
  }
}

// confirmDelete shows the delete confirmation. If the target vault is locked
// the dialog ALSO asks for the master password — a one-shot authorization
// that does NOT unlock the vault, so its values are never exposed to a
// sniffing process. Resolves to { password } on confirm (password "" when
// the vault is already unlocked), or null when cancelled.
async function confirmDelete(vault, title, message) {
  const locked = vaultLocked(vault);
  const o = { title, danger: true, okText: "delete", message };
  if (locked) {
    o.message = message + "\n\nThis vault is locked — enter the master password to authorize the delete. The vault stays locked.";
    o.fields = [{ key: "password", label: "master password", type: "password", placeholder: "password",
      validate: (v) => (v ? null : "password required") }];
  }
  const r = await openDialog(o);
  if (!r) return null;
  return { password: locked ? r.password : "" };
}

// Wave-1 heuristic for the default member (Wave-2 naming refactor replaces it).
function defaultish(name) { return name === "default"; }

// ---- reusable dialog ----------------------------------------------------

// openDialog shows the modal. With `fields` it resolves to {key: value}
// (or null on cancel); without fields it is a confirm (true/false).
function openDialog(o) {
  o = o || {};
  return new Promise((resolve) => {
    const dlg = $("#dialog"), title = $("#dialog-title"), msg = $("#dialog-msg");
    const box = $("#dialog-fields"), err = $("#dialog-error"), ok = $("#dialog-ok"), cancel = $("#dialog-cancel");
    const fields = o.fields || [];
    let done = false;

    title.textContent = o.title || "";
    if (o.message) { msg.textContent = o.message; msg.hidden = false; } else { msg.hidden = true; }
    ok.textContent = o.okText || "ok";
    ok.classList.toggle("btn-danger", !!o.danger);
    ok.classList.toggle("btn-primary", !o.danger);
    err.textContent = "";
    box.innerHTML = "";
    box.hidden = fields.length === 0;

    const inputs = {};
    fields.forEach((f) => {
      if (f.type === "checkbox") {
        const cw = el("label", "field check");
        const cb = el("input"); cb.type = "checkbox"; cb.checked = !!f.value;
        cw.appendChild(cb); cw.appendChild(el("span", "field-label", f.label || ""));
        box.appendChild(cw); inputs[f.key] = cb;
        return;
      }
      if (f.type === "checklist") {
        const cw = el("div", "field");
        if (f.label) cw.appendChild(el("span", "field-label", f.label));
        const list = el("div", "checklist");
        if (!(f.options || []).length) list.appendChild(el("span", "muted", "no env-vars in this scope"));
        (f.options || []).forEach((opt) => {
          const row = el("label", "check-row");
          const cb = el("input"); cb.type = "checkbox"; cb.value = opt; cb.checked = f.allChecked !== false;
          row.appendChild(cb); row.appendChild(el("span", "mono", opt));
          list.appendChild(row);
        });
        cw.appendChild(list); box.appendChild(cw); inputs[f.key] = list;
        return;
      }
      if (f.type === "path") {
        const pwrap = el("label", "field");
        if (f.label) pwrap.appendChild(el("span", "field-label", f.label));
        const prow = el("div", "path-row");
        const pin = el("input", "input mono");
        pin.type = "text"; pin.placeholder = f.placeholder || ""; pin.value = f.value || "";
        pin.autocomplete = "off"; pin.spellcheck = false; pin.autocapitalize = "off";
        const browse = el("button", "btn btn-ghost sm path-browse", "browse…");
        browse.type = "button";
        browse.onclick = async () => { const p = await pickDirectory(pin.value); if (p) { pin.value = p; err.textContent = ""; } };
        pin.oninput = () => { err.textContent = ""; };
        pin.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); submit(); } };
        prow.appendChild(pin); prow.appendChild(browse);
        pwrap.appendChild(prow); box.appendChild(pwrap); inputs[f.key] = pin;
        return;
      }
      const wrap = el("label", "field");
      if (f.label) wrap.appendChild(el("span", "field-label", f.label));
      const isArea = f.type === "textarea";
      const inp = el(isArea ? "textarea" : "input", "input mono" + (isArea ? " area" : ""));
      if (!isArea) inp.type = f.type || "text";
      inp.placeholder = f.placeholder || "";
      inp.value = f.value || "";
      inp.autocomplete = f.type === "password" ? "new-password" : "off";
      inp.spellcheck = false; inp.autocapitalize = "off";
      if (isArea) inp.rows = 8;
      wrap.appendChild(inp); box.appendChild(wrap); inputs[f.key] = inp;
      inp.oninput = () => { err.textContent = ""; };
      // Enter submits single-line inputs; in a textarea Enter inserts a newline.
      if (!isArea) inp.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); submit(); } };
    });

    dlg.hidden = false;
    setTimeout(() => { const t = fields.length ? inputs[fields[0].key] : ok; t.focus(); if (fields.length && inputs[fields[0].key].select) inputs[fields[0].key].select(); }, 30);

    function cleanup() { dlg.hidden = true; ok.onclick = cancel.onclick = null; document.removeEventListener("keydown", onKey, true); }
    function finish(v) { if (done) return; done = true; cleanup(); resolve(v); }
    function submit() {
      if (!fields.length) { finish(true); return; }
      const vals = {};
      for (const f of fields) {
        if (f.type === "checkbox") { vals[f.key] = inputs[f.key].checked; continue; }
        if (f.type === "checklist") {
          vals[f.key] = Array.from(inputs[f.key].querySelectorAll("input:checked")).map((c) => c.value);
          continue;
        }
        const raw = f.type === "password" || f.type === "textarea";
        const v = raw ? inputs[f.key].value : inputs[f.key].value.trim();
        const fe = f.validate ? f.validate(v) : null;
        if (fe) { err.textContent = fe; inputs[f.key].focus(); return; }
        vals[f.key] = v;
      }
      const ce = o.validate ? o.validate(vals) : null;
      if (ce) { err.textContent = ce; return; }
      finish(vals);
    }
    function dismiss() { finish(fields.length ? null : false); }
    function onKey(e) { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); dismiss(); } }
    ok.onclick = submit; cancel.onclick = dismiss;
    document.addEventListener("keydown", onKey, true);
  });
}
function dialogOpen() { return !$("#dialog").hidden; }

function joinPath(base, name) { return base.endsWith("/") ? base + name : base + "/" + name; }

// _buildDirPickerLoad builds the async load function for the directory (and
// optionally file) picker. When fileMode is true the picker shows files
// alongside directories; clicking a file resolves immediately with its path
// instead of navigating into it. The "Use this directory" button is hidden in
// file mode (selecting a file is the terminal action).
function _buildDirPickerLoad(pathEl, listEl, errEl, cur, finish, fileMode) {
  return async function load(path) {
    errEl.textContent = "";
    try {
      const qs = (path ? "path=" + enc(path) : "") + (fileMode ? (path ? "&include_files=1" : "include_files=1") : "");
      const d = await api("GET", "/api/fs/listdir" + (qs ? "?" + qs : ""));
      cur.value = d.path; pathEl.textContent = d.path;
      listEl.innerHTML = "";
      if (d.parent) {
        const up = el("button", "dirpicker-item up");
        up.appendChild(el("span", "di-ico", "↑")); up.appendChild(el("span", null, ".."));
        up.onclick = () => load(d.parent);
        listEl.appendChild(up);
      }
      if (!d.entries.length) {
        listEl.appendChild(el("div", "muted dirpicker-empty", fileMode ? "empty directory" : "no subfolders"));
      }
      d.entries.forEach((e) => {
        const it = el("button", "dirpicker-item" + (!e.is_dir ? " file" : ""));
        it.appendChild(el("span", "di-ico", e.is_dir ? "📁" : "📄")); it.appendChild(el("span", null, e.name));
        if (e.is_dir) {
          it.onclick = () => load(joinPath(cur.value, e.name));
        } else {
          // Clicking a file in file mode resolves the picker with its full path.
          it.onclick = () => finish(joinPath(cur.value, e.name));
        }
        listEl.appendChild(it);
      });
    } catch (e) { errEl.textContent = e.message; }
  };
}

// pickDirectory opens the daemon-backed directory browser and resolves to the
// chosen absolute path, or null if cancelled. Browsers can't return a real OS
// path from a native file dialog, so byn lists directories via the daemon
// (which runs as the user and sees only what the user can already read).
function pickDirectory(start) {
  return new Promise((resolve) => {
    const dlg = $("#dirpicker"), pathEl = $("#dirpicker-path"), listEl = $("#dirpicker-list");
    const errEl = $("#dirpicker-error"), use = $("#dirpicker-use"), cancel = $("#dirpicker-cancel");
    const cur = { value: start || "" };
    let done = false;
    const load = _buildDirPickerLoad(pathEl, listEl, errEl, cur, finish, false);
    function cleanup() { dlg.hidden = true; use.onclick = cancel.onclick = null; document.removeEventListener("keydown", onKey, true); }
    function finish(v) { if (done) return; done = true; cleanup(); resolve(v); }
    function onKey(e) { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); finish(null); } }
    use.onclick = () => finish(cur.value);
    cancel.onclick = () => finish(null);
    document.addEventListener("keydown", onKey, true);
    dlg.hidden = false;
    load(cur.value);
  });
}

// pickFilePath opens the daemon-backed directory/file browser in file-pick mode
// and resolves to the chosen absolute file path, or null if cancelled. Files
// are shown alongside directories (dirs first); clicking a file selects it.
function pickFilePath(start) {
  return new Promise((resolve) => {
    const dlg = $("#dirpicker"), pathEl = $("#dirpicker-path"), listEl = $("#dirpicker-list");
    const errEl = $("#dirpicker-error"), use = $("#dirpicker-use"), cancel = $("#dirpicker-cancel");
    const cur = { value: start || "" };
    let done = false;
    const load = _buildDirPickerLoad(pathEl, listEl, errEl, cur, finish, true);
    // In file mode "use" selects the current directory (not useful here, so hide it).
    const prevUseHidden = use.hidden;
    use.hidden = true;
    function cleanup() { dlg.hidden = true; use.hidden = prevUseHidden; use.onclick = cancel.onclick = null; document.removeEventListener("keydown", onKey, true); }
    function finish(v) { if (done) return; done = true; cleanup(); resolve(v); }
    function onKey(e) { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); finish(null); } }
    cancel.onclick = () => finish(null);
    document.addEventListener("keydown", onKey, true);
    dlg.hidden = false;
    load(cur.value);
  });
}

// ---- tree ---------------------------------------------------------------

function label(name, level, isDefault) {
  const wrap = el("span", "lbl");
  wrap.appendChild(el("span", "lvl lvl-" + level, level[0]));
  wrap.appendChild(el("span", "lbl-name", name));
  if (isDefault) wrap.appendChild(el("span", "tag-default", "default"));
  return wrap;
}
function treeNode(cls, inner, onMain, actions) {
  const node = el("div", "node " + cls);
  const main = el("div", "node-main"); main.appendChild(inner); main.onclick = onMain;
  node.appendChild(main);
  (actions || []).filter(Boolean).forEach((a) => node.appendChild(a));
  return node;
}
function nodeAct(iconName, cls, title, fn) {
  const b = el("button", "node-act " + (cls || ""));
  b.title = title; b.appendChild(icon(iconName));
  b.onclick = (e) => { e.stopPropagation(); fn(); };
  return b;
}
function twistSpan(onToggle) {
  const t = el("span", "twist", "▸");
  t.onclick = (e) => { e.stopPropagation(); onToggle(); };
  return t;
}

async function renderTree() {
  const tree = $("#tree"); tree.innerHTML = "";
  const st = await api("GET", "/api/status");
  if (st && st.version) setHelpVersion(st.version);
  state.vaults = (st.vaults || []).filter((v) => v.initialized);
  for (const v of state.vaults) {
    const open = state.open.vaults.has(v.name);
    const inner = el("span", "node-inner");
    inner.appendChild(twistSpan(() => toggleVault(v.name)));
    inner.appendChild(label(v.name, "vault", defaultish(v.name)));
    const actions = [
      v.locked ? nodeAct("lock", "locked", "unlock vault", () => unlockVault(v.name))
               : nodeAct("unlock", "unlocked", "unlocked — the daemon holds the key; revealing values may still ask this browser to authorize", () => lockVault(v.name)),
      nodeAct("key", "passwd", "change password", () => changePassword(v.name)),
      defaultish(v.name) ? null : nodeAct("pencil", "ren", "rename vault", () => renameVault(v.name)),
      defaultish(v.name) ? null : nodeAct("trash", "del", "delete vault", () => deleteVault(v.name)),
    ];
    tree.appendChild(treeNode(
      "vault" + (open ? " open" : "") + (state.scope.vault === v.name ? " active" : ""),
      inner, () => navVault(v.name), actions));
    if (open) await renderTreeProjects(tree, v.name);
  }
  if (state.vaults.length === 0) {
    const hint = el("div", "tree-empty", "no vaults yet");
    tree.appendChild(hint);
  }
}
async function renderTreeProjects(tree, vault) {
  let data; try { data = await api("GET", "/api/projects?vault=" + enc(vault)); } catch { return; }
  for (const p of data.projects || []) {
    const key = vault + "/" + p.name;
    const open = state.open.projects.has(key);
    const active = state.scope.vault === vault && state.scope.project === p.name;
    const inner = el("span", "node-inner");
    inner.appendChild(twistSpan(() => toggleProject(vault, p.name)));
    inner.appendChild(label(p.name, "project", defaultish(p.name)));
    tree.appendChild(treeNode(
      "project depth-1" + (open ? " open" : "") + (active ? " active" : ""),
      inner, () => navProject(vault, p.name),
      [defaultish(p.name) ? null : nodeAct("pencil", "ren", "rename project", () => renameProject(vault, p.name)),
       defaultish(p.name) ? null : nodeAct("trash", "del", "delete project", () => deleteProject(vault, p.name))]));
    if (open) await renderTreeEnvs(tree, vault, p.name);
  }
}
async function renderTreeEnvs(tree, vault, project) {
  let data;
  try { data = await api("GET", "/api/envs?vault=" + enc(vault) + "&project=" + enc(project)); } catch { return; }
  for (const en of data.envs || []) {
    const active = state.scope.vault === vault && state.scope.project === project && state.scope.env === en.name && state.view === "entries";
    const inner = el("span", "node-inner");
    inner.appendChild(el("span", "leaf-mark", active ? "●" : "○"));
    inner.appendChild(label(en.name, "env", en.is_default));
    tree.appendChild(treeNode(
      "env depth-2" + (active ? " active" : ""),
      inner, () => selectScope(vault, project, en.name),
      [en.is_default ? null : nodeAct("pencil", "ren", "rename env", () => renameEnv(vault, project, en.name)),
       en.is_default ? null : nodeAct("trash", "del", "delete env", () => deleteEnv(vault, project, en.name))]));
  }
}

async function toggleVault(v) { const s = state.open.vaults; s.has(v) ? s.delete(v) : s.add(v); await renderTree(); }
async function toggleProject(v, p) { const k = v + "/" + p, s = state.open.projects; s.has(k) ? s.delete(k) : s.add(k); await renderTree(); }

async function navVault(name) {
  await guardDirtyNav(async () => {
    state.scope = { vault: name, project: "", env: "" };
    state.open.vaults.add(name); state.view = "projects";
    // Push the vault-browse URL so the view is bookmarkable and back/forward works.
    history.pushState(null, "", vaultPath(name));
    await renderTree(); renderContent();
  });
}
async function navProject(vault, project) {
  await guardDirtyNav(async () => {
    state.scope = { vault, project, env: "" };
    state.open.vaults.add(vault); state.open.projects.add(vault + "/" + project); state.view = "envs";
    // Push the env-browse URL so the view is bookmarkable and back/forward works.
    history.pushState(null, "", projectPath(vault, project));
    await renderTree(); renderContent();
  });
}
async function selectScope(vault, project, env) {
  await guardDirtyNav(async () => {
    state.scope = { vault, project, env }; state.view = "entries";
    // Push the scope URL into history so the user can bookmark or copy the link,
    // and so back/forward navigate between scopes correctly.
    history.pushState(null, "", entriesPath(vault, project, env));
    await renderTree(); await loadEntries();
  });
}

// ---- per-vault lock / create / delete -----------------------------------

async function unlockVault(name) {
  const refresh = async () => {
    await renderTree();
    if (state.scope.vault === name && state.view === "entries") await loadEntries(); else renderContent();
  };
  // Touch ID first when this vault has an unlock-capable passkey; on cancel or
  // any failure, fall through to the master-password dialog.
  if (window.bynPasskey && (await window.bynPasskey.canUnlock(name))) {
    try {
      const r = await window.bynPasskey.signIn(name);
      if (r && r.unlocked) { toast("unlocked " + name + " with Touch ID"); await refresh(); return; }
    } catch (e) { /* fall through to password */ }
  }
  const r = await openDialog({ title: "Unlock " + name, okText: "unlock",
    message: `Enter the master password for “${name}”.`,
    fields: [{ key: "password", label: "master password", type: "password" }] });
  if (!r) return;
  try {
    await api("POST", "/api/unlock", { vault: name, password: r.password });
    toast("unlocked " + name); await refresh();
  } catch (e) { toast(e.message, true); }
}
async function lockVault(name) {
  try {
    await api("POST", "/api/lock", { vault: name });
    toast("locked " + name); await renderTree();
    if (state.scope.vault === name && state.view === "entries") await loadEntries();
  } catch (e) { toast(e.message, true); }
}

// lockAllVaults locks every unlocked vault in one shot (daemon Name="*").
// Bound to the `l a` chord and used for a fast "lock everything" panic.
async function lockAllVaults() {
  try {
    await api("POST", "/api/lock", { vault: "*" });
    toast("locked all vaults");
    await renderTree();
    if (state.view === "entries") await loadEntries();
  } catch (e) { toast(e.message, true); }
}

// busyEditing reports whether the user is mid-interaction (a dialog or an
// inline edit), so the background sync doesn't clobber their input.
function busyEditing() {
  return dialogOpen() || !!document.querySelector("#content-body .inline-input, #content-body .trow.editing");
}

// syncStatus keeps the browser's lock state in line with the daemon — the
// source of truth — so locking/unlocking from the CLI or TUI is reflected in
// the portal. Without it the UI could show a "locked" banner over a vault
// that is actually unlocked (values revealable), or vice-versa. state.vaults
// is always refreshed so vaultLocked() is accurate; the DOM is only
// re-rendered when a lock state actually changed and the user isn't editing.
async function syncStatus() {
  let st;
  try { st = await api("GET", "/api/status"); } catch { return; }
  const fresh = (st.vaults || []).filter((v) => v.initialized);
  const prev = new Map(state.vaults.map((v) => [v.name, v.locked]));
  let changed = fresh.length !== state.vaults.length;
  let scopeChanged = false;
  for (const v of fresh) {
    if (prev.get(v.name) !== v.locked) {
      changed = true;
      if (v.name === state.scope.vault) scopeChanged = true;
    }
  }
  state.vaults = fresh; // keep the cache accurate even if we skip re-render
  if (!changed || busyEditing()) return;
  await renderTree();
  if (scopeChanged && state.view === "entries") await loadEntries();
}

// startStatusSync polls the daemon every 2s. Recursive setTimeout (not
// setInterval) so a slow poll never overlaps the next.
function startStatusSync() {
  const tick = async () => { await syncStatus(); setTimeout(tick, 2000); };
  setTimeout(tick, 2000);
}
// changePassword rotates a vault's master password. Only the wrapping
// changes — the vault key and all secrets are untouched, and the lock state
// is preserved. The current password is required (a forgotten password is
// unrecoverable by design).
async function changePassword(name) {
  const r = await openDialog({
    title: "Change password", okText: "change",
    message: `Set a new master password for “${name}”. Only the wrapping changes — your secrets stay intact.`,
    fields: [
      { key: "old", label: "current password", type: "password", placeholder: "current password",
        validate: (v) => (v ? null : "current password required") },
      { key: "neu", label: "new password", type: "password", placeholder: "new password (min 8)",
        validate: (v) => (v.length >= 8 ? null : "at least 8 characters") },
      { key: "confirm", label: "confirm new password", type: "password", placeholder: "repeat new password" },
    ],
    validate: (vals) => (vals.neu === vals.confirm ? null : "new passwords do not match"),
  });
  if (!r) return;
  try {
    await api("POST", "/api/vault/passwd", { vault: name, old_password: r.old, new_password: r.neu });
    toast("changed password for " + name);
  } catch (e) { toast(e.message, true); }
}
async function createVault() {
  const r = await openDialog({
    title: "New vault", okText: "create",
    message: "A new vault derives a key from your password — this can take a few seconds.",
    fields: [
      { key: "name", label: "vault name", placeholder: "vault name", validate: validateScopeName },
      { key: "password", label: "master password", type: "password", validate: (v) => v.length ? null : "password is required" },
      { key: "confirm", label: "confirm password", type: "password" },
    ],
    validate: (vals) => (vals.password !== vals.confirm ? "passwords don’t match" : null),
  });
  if (!r) return;
  toast("creating vault…");
  try {
    await api("POST", "/api/vaults", { name: r.name, password: r.password });
    toast("created vault " + r.name);
    state.open.vaults.add(r.name); await selectScope(r.name, "default", "default");
  } catch (e) { toast(e.message, true); }
}

async function deleteVault(name) {
  const c = await confirmDelete(name, "Delete vault",
    `Delete vault “${name}”?\n\nThis removes EVERYTHING in this vault — projects, envs, vars, passkeys, audit log.\nThis cannot be undone.`);
  if (!c) return;
  try {
    await apiWithAuth("POST", "/api/vault/delete", { name, password: c.password }, name); toast("deleted vault " + name);
    if (state.scope.vault === name) { state.scope = { vault: "", project: "", env: "" }; $("#content-body").innerHTML = ""; $("#crumbs").innerHTML = ""; }
    await renderTree();
  } catch (e) { toast(e.message, true); }
}
async function deleteProject(vault, name) {
  const c = await confirmDelete(vault, "Delete project",
    `Delete project “${name}” in ${vault}?\n\nAll envs and their vars are deleted.\nThis cannot be undone.`);
  if (!c) return;
  try {
    await apiWithAuth("POST", "/api/project/delete", { vault, name, password: c.password }, vault); toast("deleted project " + name);
    state.open.projects.delete(vault + "/" + name);
    if (state.scope.vault === vault && state.scope.project === name) { state.scope.project = ""; state.scope.env = ""; $("#content-body").innerHTML = ""; }
    await renderTree();
  } catch (e) { toast(e.message, true); }
}
async function deleteEnv(vault, project, name) {
  const c = await confirmDelete(vault, "Delete env",
    `Delete env “${name}” in ${vault}/${project}?\n\nAll env-vars in it are deleted.\nThis cannot be undone.`);
  if (!c) return;
  try {
    await apiWithAuth("POST", "/api/env/delete", { vault, project, name, password: c.password }, vault); toast("deleted env " + name);
    if (state.scope.vault === vault && state.scope.project === project && state.scope.env === name) { state.scope.env = ""; $("#content-body").innerHTML = ""; }
    await renderTree();
  } catch (e) { toast(e.message, true); }
}
// renameDialog shows a rename dialog for a scope. If the target vault is
// locked it also asks for the master password — a one-shot authorization
// that doesn't unlock the vault. Resolves to { name, password } (password ""
// when unlocked), or null when cancelled or unchanged.
async function renameDialog(vault, title, message, current, placeholder) {
  const locked = vaultLocked(vault);
  const o = { title, okText: "rename", message,
    fields: [{ key: "name", label: "new name", placeholder, value: current, validate: validateScopeName }] };
  if (locked) {
    o.message = message + "\n\nThis vault is locked — enter the master password to authorize.";
    o.fields.push({ key: "password", label: "master password", type: "password", placeholder: "password",
      validate: (v) => (v ? null : "password required") });
  }
  const r = await openDialog(o);
  if (!r || r.name === current) return null;
  return { name: r.name, password: locked ? r.password : "" };
}

// renameVault renames a vault. The vault is LEFT LOCKED afterwards — renaming
// evicts its in-memory key — so re-unlock to keep using it.
async function renameVault(name) {
  const c = await renameDialog(name, "Rename vault",
    `Rename vault “${name}”. It will be locked afterwards — re-unlock to keep using it.`, name, "vault name");
  if (!c) return;
  try {
    await apiWithAuth("POST", "/api/vault/rename", { old_name: name, new_name: c.name, password: c.password }, name);
    toast(`renamed vault → ${c.name}`);
    if (state.open.vaults.has(name)) { state.open.vaults.delete(name); state.open.vaults.add(c.name); }
    if (state.scope.vault === name) state.scope.vault = c.name;
    await renderTree();
    if (state.view === "entries" && state.scope.vault === c.name) await loadEntries(); else renderContent();
  } catch (e) { toast(e.message, true); }
}
async function renameProject(vault, name) {
  const c = await renameDialog(vault, "Rename project", `Rename project “${name}” in ${vault}.`, name, "project name");
  if (!c) return;
  try {
    await api("POST", "/api/project/rename", { vault, old_name: name, new_name: c.name, password: c.password });
    toast(`renamed project → ${c.name}`);
    const oldKey = vault + "/" + name;
    if (state.open.projects.has(oldKey)) { state.open.projects.delete(oldKey); state.open.projects.add(vault + "/" + c.name); }
    if (state.scope.vault === vault && state.scope.project === name) state.scope.project = c.name;
    await renderTree(); renderContent();
  } catch (e) { toast(e.message, true); }
}
async function renameEnv(vault, project, name) {
  const c = await renameDialog(vault, "Rename env", `Rename env “${name}” in ${vault}/${project}.`, name, "env name");
  if (!c) return;
  try {
    await api("POST", "/api/env/rename", { vault, project, old_name: name, new_name: c.name, password: c.password });
    toast(`renamed env → ${c.name}`);
    if (state.scope.vault === vault && state.scope.project === project && state.scope.env === name) state.scope.env = c.name;
    await renderTree();
    if (state.view === "entries") await loadEntries(); else renderContent();
  } catch (e) { toast(e.message, true); }
}
async function createProject() {
  const r = await openDialog({ title: "New project", okText: "create",
    fields: [{ key: "name", label: "name", placeholder: "project name", validate: validateScopeName }] });
  if (!r) return;
  try {
    await api("POST", "/api/projects", { vault: state.scope.vault, name: r.name });
    toast("created project " + r.name); state.open.vaults.add(state.scope.vault); await renderTree(); renderProjectsView();
  } catch (e) { toast(e.message, true); }
}
async function createEnv() {
  const r = await openDialog({ title: "New env", okText: "create",
    fields: [{ key: "name", label: "name", placeholder: "env name", validate: validateScopeName }] });
  if (!r) return;
  try {
    await api("POST", "/api/envs", { vault: state.scope.vault, project: state.scope.project, name: r.name });
    toast("created env " + r.name); await renderTree(); renderEnvsView();
  } catch (e) { toast(e.message, true); }
}

// ---- breadcrumbs + content dispatch -------------------------------------

function renderCrumbs() {
  const c = $("#crumbs"); c.innerHTML = "";
  const s = state.scope;
  const crumb = (text, level, onclick, current) => {
    const b = el("button", "crumb" + (current ? " cur" : ""));
    b.appendChild(el("span", "crumb-lvl", level));
    b.appendChild(el("span", "crumb-name", text || "—"));
    if (onclick && text) b.onclick = onclick; else b.disabled = true;
    return b;
  };
  c.appendChild(crumb(s.vault, "vault", () => browse("projects"), state.view === "projects"));
  c.appendChild(el("span", "sep", "›"));
  c.appendChild(crumb(s.project, "project", () => browse("envs"), state.view === "envs"));
  c.appendChild(el("span", "sep", "›"));
  c.appendChild(crumb(s.env, "env", () => { state.view = "entries"; loadEntries(); }, state.view === "entries"));
  $("#legend").hidden = !(state.view === "entries" && s.env && !defaultish(s.env));
}
function browse(view) {
  state.view = view;
  if (view === "projects" && state.scope.vault) {
    history.pushState(null, "", vaultPath(state.scope.vault));
  } else if (view === "envs" && state.scope.vault && state.scope.project) {
    history.pushState(null, "", projectPath(state.scope.vault, state.scope.project));
  }
  renderContent();
}

// leaveOverlayView returns from the audit/trust/studio overlay to the most
// specific normal view the current scope supports and updates the URL.
function leaveOverlayView() {
  studioState = null;  // clear any studio session when leaving
  studioBaseline = null; // clear dirty-tracking baselines
  cfgBaseline    = null;
  if (state.scope.env) {
    state.view = "entries";
    history.pushState(null, "", entriesPath(state.scope.vault, state.scope.project, state.scope.env));
    loadEntries(); return;
  }
  if (state.scope.project) {
    state.view = "envs";
    history.pushState(null, "", projectPath(state.scope.vault, state.scope.project));
    renderContent(); return;
  }
  if (state.scope.vault) {
    state.view = "projects";
    history.pushState(null, "", vaultPath(state.scope.vault));
    renderContent(); return;
  }
  state.view = "entries"; replaceNav("/"); renderContent();
}

function renderContent() {
  renderCrumbs();
  if (state.view === "audit") return renderAuditView();
  if (state.view === "trust") return renderTrustView();
  if (state.view === "settings") return renderSettingsView();
  if (state.view === "studio") return; // studio manages its own DOM
  if (state.view === "projects") return renderProjectsView();
  if (state.view === "envs") return renderEnvsView();
  return renderEntries();
}
function createItem(text, fn) {
  const it = el("button", "browse-item add");
  it.appendChild(el("span", "lvl lvl-add", "+"));
  it.appendChild(el("span", "browse-name muted", text));
  it.onclick = fn; return it;
}
function vaultLocked(name) { const v = state.vaults.find((x) => x.name === name); return v ? v.locked : false; }
function manageRow(text, createFn) {
  // Adding/removing scopes needs the vault unlocked (daemon enforces it).
  if (vaultLocked(state.scope.vault)) {
    const it = el("button", "browse-item add locked");
    it.appendChild(el("span", "lvl lvl-add", "🔒"));
    it.appendChild(el("span", "browse-name muted", "unlock to add or remove"));
    it.onclick = () => unlockVault(state.scope.vault);
    return it;
  }
  return createItem(text, createFn);
}
// ---- audit log view -----------------------------------------------------

function toggleAudit() {
  if (state.view === "audit") { leaveOverlayView(); return; }
  if (!state.scope.vault) { toast("pick a vault first", true); return; }
  navigateGuarded("/audit");
}
async function renderAuditView() {
  const box = $("#content-body"); box.innerHTML = "";
  const vault = state.scope.vault;
  const head = el("div", "browse-head", "audit · " + vault);
  box.appendChild(head);
  try {
    const v = await api("GET", "/api/audit/verify?vault=" + enc(vault));
    const ok = v.bad_index < 0;
    head.appendChild(el("span", "verify-chip " + (ok ? "ok" : "bad"),
      ok ? `chain intact · ${v.total}` : `chain BROKEN at #${v.bad_index}`));
  } catch (_) { /* verify is best-effort */ }
  let data;
  try { data = await api("GET", "/api/audit?vault=" + enc(vault) + "&n=200"); }
  catch (e) { box.appendChild(emptyHint(e.message)); return; }
  const events = (data.events || []).slice().reverse(); // newest first
  if (!events.length) { box.appendChild(emptyHint("no audit events yet")); return; }
  const tbl = el("div", "audit-tbl");
  const hdr = el("div", "audit-row audit-head");
  ["TIME", "OP", "OUTCOME", "SCOPE", "CALLER"].forEach((h) => hdr.appendChild(el("span", null, h)));
  tbl.appendChild(hdr);
  for (const e of events) {
    const row = el("div", "audit-row" + (e.outcome && e.outcome !== "ok" ? " bad" : ""));
    row.appendChild(el("span", "a-time", fmtAuditTime(e.ts)));
    row.appendChild(el("span", "a-op", e.op + (e.command ? " " + e.command : (e.entry_name ? " " + e.entry_name : ""))));
    row.appendChild(el("span", "a-out", e.outcome + (e.error_code ? " (" + e.error_code + ")" : "")));
    const sc = el("span", "a-scope", auditScope(e));
    if (e.byn_path) sc.title = e.byn_path;
    row.appendChild(sc);
    row.appendChild(el("span", "a-caller", auditCaller(e)));
    tbl.appendChild(row);
  }
  box.appendChild(tbl);
}
function auditScope(e) {
  if (e.byn_path) return e.byn_path; // exec authorization: show the authorizing .byn
  const parts = [e.project, e.env].filter(Boolean);
  return parts.length ? parts.join("/") : "—";
}
function auditCaller(e) {
  const surface = e.caller_surface ? e.caller_surface : "";
  const who = e.caller_comm || "";
  const pid = e.caller_pid ? "·" + e.caller_pid : "";
  const s = [surface, who].filter(Boolean).join(" ") + pid;
  return s || "—";
}
function fmtAuditTime(tsNanos) {
  if (!tsNanos) return "";
  const d = new Date(tsNanos / 1e6); // ns → ms
  // Render in 24-hour format (no AM/PM) — consistent with audit log output.
  return d.toLocaleString(undefined, {
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false,
  });
}

// ---- trust list view ----------------------------------------------------

function toggleTrust() {
  if (state.view === "trust") { leaveOverlayView(); return; }
  navigateGuarded("/trust");
}
async function renderTrustView() {
  const box = $("#content-body"); box.innerHTML = "";
  box.appendChild(el("div", "browse-head", "trusted .byn files"));
  let data;
  try { data = await api("GET", "/api/trust"); }
  catch (e) { box.appendChild(emptyHint(e.message)); return; }
  const entries = data.entries || [];
  if (!entries.length) { box.appendChild(emptyHint("no trusted .byn files")); return; }
  const tbl = el("div", "trust-tbl");
  for (const t of entries) {
    const row = el("div", "trust-row");
    row.appendChild(el("span", "t-hash", (t.sha256 || "").slice(0, 12)));
    const p = el("span", "t-path", t.path); p.title = t.path;
    row.appendChild(p);
    const actWrap = el("div", "trust-row-acts");
    const editBtn = el("button", "btn btn-ghost sm", "edit");
    editBtn.title = "open in .byn studio";
    editBtn.onclick = () => openStudioForPath(t.path);
    actWrap.appendChild(editBtn);
    const revokeBtn = el("button", "btn btn-ghost sm", "revoke");
    revokeBtn.onclick = () => revokeTrust(t.path);
    actWrap.appendChild(revokeBtn);
    row.appendChild(actWrap);
    tbl.appendChild(row);
  }
  box.appendChild(tbl);
}
async function revokeTrust(path) {
  const ok = await openDialog({ title: "Revoke trust", danger: true, okText: "revoke",
    message: `Stop trusting ${path}?\nbyn will refuse to apply its scope until you run “byn trust” again.` });
  if (!ok) return;
  try {
    await api("POST", "/api/trust/remove", { path });
    toast("revoked trust");
    renderTrustView();
  } catch (e) { toast(e.message, true); }
}

// ---- settings panel (global config editor) ----------------------------------
//
// Shows the global $BYN_DIR/config TOML file with a visual form as the
// default view, and a raw TOML textarea as the alternate mode — mirroring the
// .byn studio builder/raw pattern. Mode-switching uses openDialog (never
// browser confirm/alert). Save is credential-gated (apiWithAuth handles the
// step-up). On success the panel shows the daemon's change_notes so the user
// knows what took effect vs what needs a restart.

function toggleSettings() {
  if (state.view === "settings") { leaveOverlayView(); return; }
  navigateGuarded("/settings");
}

// DEFAULT_CONFIG_TEMPLATE is shown in raw mode when the config file is absent.
const DEFAULT_CONFIG_TEMPLATE = `# byn global configuration
# Save to apply changes live (hot-apply) or restart the daemon for structural ones.

[ui]
# enabled = true        # set false to disable the portal entirely
# port    = 2967        # loopback port the portal listens on (needs restart)
# reveal_hide_after = "15s"  # re-mask revealed secret values after this long; "0s" = never (hot-apply)

[daemon]
# idle_timeout = "0s"   # lock all vaults after inactivity; "0s" disables (hot-apply)

[security]
# session_ttl  = "12h"  # absolute session lifetime; "0s" = no absolute cap (hot-apply)
# session_idle = "0s"   # sliding idle window; "0s" = inherit [daemon] idle_timeout
# privsep = true        # run trusted-.byn exec children as _byn-exec — needs \`sudo byn setup\` + a daemon restart
`;

// cfgState holds the mutable state for the settings panel (analogous to
// studioState for the .byn studio). Recreated on each renderSettingsView call.
let cfgState = null;

// cfgReset re-fetches config.get and repopulates whichever mode is active from
// the SAVED state. Confirms via byn modal (same pattern as studioReset).
async function cfgReset() {
  if (!cfgState) return;
  const confirmed = await openDialog({
    title:   "Reset settings?",
    message: "Reset to the last saved config? Any unsaved changes in the editor will be lost.",
    okText:  "reset",
  });
  if (!confirmed) return;
  let d;
  try {
    d = await api("GET", "/api/config");
  } catch (e) {
    if (cfgState.notesEl) showConfigNotes(cfgState.notesEl, ["could not reload config: " + e.message], true);
    return;
  }
  const p = d.parsed || null;
  const raw = d.content || "";
  const parseError = d.parse_error || "";
  if (cfgState.rawMode) {
    // In raw mode: reload the textarea from the saved file (or template).
    const newRaw = raw || DEFAULT_CONFIG_TEMPLATE;
    cfgState.rawContent = newRaw;
    if (cfgState.rawTA) cfgState.rawTA.value = newRaw;
    // Clear any lingering inline notices.
    if (cfgState.notesEl) { cfgState.notesEl.hidden = true; cfgState.notesEl.textContent = ""; }
    // After reset the content equals the new baseline — clear dirty flag.
    cfgBaseline = newRaw;
  } else {
    // In form mode: repopulate form fields from parsed (or switch to raw if unparseable).
    if (!p) {
      // File is corrupt — fall back to raw with a notice.
      cfgState.rawMode = true;
      cfgState.rawContent = raw || DEFAULT_CONFIG_TEMPLATE;
      if (cfgState.rawTA) cfgState.rawTA.value = cfgState.rawContent;
      if (cfgState.rawPanel)  cfgState.rawPanel.hidden  = false;
      if (cfgState.formPanel) cfgState.formPanel.hidden = true;
      if (cfgState.modeToggle) { cfgState.modeToggle.textContent = "switch to form"; cfgState.modeToggle.dataset.mode = "raw"; }
      if (cfgState.notesEl) showConfigNotes(cfgState.notesEl, ["config could not be parsed — showing raw mode. Fix the error to use the visual editor."], true);
      // Baseline is already set in renderSettingsView; not reached here.
      return;
    }
    cfgState.uiEnabled     = p.ui_enabled;
    cfgState.uiPort        = p.ui_port;
    cfgState.revealHideAfter = p.reveal_hide_after;
    cfgState.idleTimeout   = p.idle_timeout;
    cfgState.sessionTTL    = p.session_ttl;
    cfgState.sessionIdle   = p.session_idle;
    cfgState.privsep       = p.privsep === true;
    setRevealHideAfter(p.reveal_hide_after);
    // Re-render the form to reflect the reset values.
    // renderSettingsView re-creates cfgState and sets cfgBaseline.
    renderSettingsView();
    return;
  }
  toast("settings reset to saved state");
}

// renderContent calls renderSettingsView for state.view === "settings".
// We add the case in the dispatch chain by inserting it before the existing
// view checks — but renderContent is declared earlier in the file, so we patch
// it by adding the branch inside the function that calls renderContent.

async function renderSettingsView() {
  const box = $("#content-body"); box.innerHTML = "";
  box.appendChild(el("div", "browse-head", "settings · global config"));

  let configPath = "";
  let configContent = "";
  let configParsed = null;    // ConfigParsed from the daemon; null → fall back to raw
  let parseError  = "";

  try {
    const d = await api("GET", "/api/config");
    configPath   = d.path    || "";
    configContent = d.content || "";
    configParsed = d.parsed  || null;
    parseError   = d.parse_error || "";
  } catch (e) {
    box.appendChild(emptyHint("could not load config: " + e.message));
    return;
  }
  if (configParsed) setRevealHideAfter(configParsed.reveal_hide_after);

  // cfgState tracks visual-form values and the current mode (form vs raw).
  // rawMode starts false (form is the default) unless the file is unparseable.
  cfgState = {
    rawMode:    !!parseError,   // force raw when the saved file is corrupt
    // Visual-form fields, seeded from the daemon-parsed values (or defaults).
    uiEnabled:     configParsed ? configParsed.ui_enabled     : true,
    uiPort:        configParsed ? configParsed.ui_port        : 2967,
    revealHideAfter: configParsed ? configParsed.reveal_hide_after : "15s",
    idleTimeout:   configParsed ? configParsed.idle_timeout   : "15m0s",
    sessionTTL:    configParsed ? configParsed.session_ttl     : "12h0m0s",
    sessionIdle:   configParsed ? configParsed.session_idle    : "0s",
    privsep:       configParsed ? configParsed.privsep === true : false,
    // Raw textarea content, seeded lazily when switching to raw mode.
    rawContent: configContent || DEFAULT_CONFIG_TEMPLATE,
    // DOM refs populated below.
    formPanel:  null,
    rawPanel:   null,
    rawTA:      null,
    modeToggle: null,
    resetBtn:   null,
    notesEl:    null,
    saveBtn:    null,
  };

  // Baseline for dirty-tracking: capture the serialized form content right
  // after cfgState is initialised so the guard only fires when the user has
  // actually changed something since the panel opened (or last saved/reset).
  cfgBaseline = cfgState.rawMode
    ? (cfgState.rawContent || "")
    : serializeCfg(cfgState);

  // Config file path.
  const pathRow = el("div", "cfg-path-row");
  pathRow.appendChild(el("span", "cfg-path-label", "config file"));
  const pathEl = el("span", "cfg-path mono");
  pathEl.textContent = configPath;
  pathEl.title = configPath;
  pathRow.appendChild(pathEl);
  box.appendChild(pathRow);

  // Parse-error notice (only visible when the file is corrupt and we forced raw).
  if (parseError) {
    const warn = el("div", "cfg-parse-warn");
    warn.textContent = "note: could not parse saved config — showing raw mode. Fix the error to use the visual editor.";
    box.appendChild(warn);
  }

  // Mode-toggle bar: "form" ↔ "raw" (mirrors the .byn studio modeToggle).
  const modeBar = el("div", "cfg-mode-bar");
  const modeToggle = el("button", "btn btn-ghost sm cfg-mode-toggle", "switch to raw");
  modeToggle.dataset.mode = "form";  // current mode
  modeToggle.onclick = toggleCfgMode;
  cfgState.modeToggle = modeToggle;
  // In raw mode (corrupt file) update initial button label.
  if (cfgState.rawMode) {
    modeToggle.textContent = "switch to form";
    modeToggle.dataset.mode = "raw";
  }
  modeBar.appendChild(modeToggle);

  // Reset button — reloads the saved config and repopulates the active mode.
  const resetBtn = el("button", "btn btn-ghost sm cfg-reset-btn", "reset");
  resetBtn.title = "reset to the last saved config (discards unsaved edits)";
  resetBtn.onclick = cfgReset;
  cfgState.resetBtn = resetBtn;
  modeBar.appendChild(resetBtn);

  box.appendChild(modeBar);

  // Key reference card — hot-apply vs restart.
  const ref = el("div", "cfg-ref");
  const refTitle = el("div", "cfg-ref-title", "key reference");
  ref.appendChild(refTitle);
  const refRows = [
    ["[ui] enabled",            "hot-apply on save"],
    ["[ui] port",               "hot-apply on save (needs restart to rebind)"],
    ["[ui] reveal_hide_after",  "hot-apply on save"],
    ["[daemon] idle_timeout",   "hot-apply on save"],
    ["[security] session_ttl",  "needs daemon restart (not hot-applied)"],
    ["[security] session_idle", "needs daemon restart (not hot-applied)"],
    ["[security] privsep",      "needs `sudo byn setup` + daemon restart"],
  ];
  for (const [k, v] of refRows) {
    const row = el("div", "cfg-ref-row");
    const key = el("span", "cfg-ref-key mono");
    key.textContent = k;
    const val = el("span", "cfg-ref-val");
    val.textContent = v;
    row.appendChild(key); row.appendChild(val);
    ref.appendChild(row);
  }
  box.appendChild(ref);

  // ── Visual form panel ──────────────────────────────────────────────────────
  const formPanel = el("div", "cfg-form");
  cfgState.formPanel = formPanel;

  // [ui] section
  const uiCard = cfgFormCard("ui");

  // enabled toggle
  const enabledRow = el("label", "cfg-form-row");
  const enabledCb  = el("input"); enabledCb.type = "checkbox"; enabledCb.checked = cfgState.uiEnabled;
  enabledCb.onchange = () => { cfgState.uiEnabled = enabledCb.checked; };
  const enabledText = el("span", null, "enabled");
  const enabledHint = el("span", "cfg-field-hint", "enable the local web portal");
  enabledRow.appendChild(enabledCb); enabledRow.appendChild(enabledText);
  enabledRow.appendChild(enabledHint);
  uiCard.appendChild(enabledRow);

  // port number input
  const portWrap = el("div", "cfg-form-row");
  const portLabel = el("label", "cfg-field-label"); portLabel.textContent = "port";
  const portInput = el("input", "input mono cfg-port-input");
  portInput.type = "number"; portInput.min = "1"; portInput.max = "65535";
  portInput.value = String(cfgState.uiPort);
  portInput.placeholder = "1–65535";
  portInput.autocomplete = "off";
  portInput.oninput = () => {
    const v = parseInt(portInput.value, 10);
    if (portInput.value.trim() !== "" && (isNaN(v) || v < 1 || v > 65535)) {
      portInput.setCustomValidity("port must be 1–65535");
      portInput.reportValidity();
    } else {
      portInput.setCustomValidity("");
    }
    cfgState.uiPort = (isNaN(v) || v < 1 || v > 65535) ? null : v;
  };
  const portHint = el("span", "cfg-field-hint", "hot-apply; needs restart to rebind");
  portLabel.appendChild(portInput);
  portWrap.appendChild(portLabel); portWrap.appendChild(portHint);
  uiCard.appendChild(portWrap);

  // reveal_hide_after: a single seconds input (reveal timeouts are short).
  // Stored as a Go duration string; "0s" (0 seconds) disables auto-hide.
  const revWrap = el("div", "cfg-form-row");
  const revLabel = el("span", "cfg-field-label"); revLabel.textContent = "reveal hide after";
  const revPair = el("div", "cfg-idle-pair");
  const revSecsIn = el("input", "input mono cfg-idle-num");
  revSecsIn.type = "number"; revSecsIn.min = "0"; revSecsIn.step = "1";
  const revInit = parseDurationToMins(cfgState.revealHideAfter || "15s");
  revSecsIn.value = String(revInit.mins * 60 + revInit.secs);
  revSecsIn.placeholder = "15";
  revSecsIn.autocomplete = "off";
  revSecsIn.title = "seconds";
  revSecsIn.oninput = () => {
    const s = Math.max(0, parseInt(revSecsIn.value, 10) || 0);
    cfgState.revealHideAfter = serializeDuration(Math.floor(s / 60), s % 60);
  };
  // Normalize cfgState.revealHideAfter to the serializer's form up front.
  revSecsIn.oninput();
  revPair.appendChild(revSecsIn);
  revPair.appendChild(el("span", "cfg-idle-unit", "s"));
  const revHint = el("span", "cfg-field-hint", "re-mask revealed values after this long; 0 = never · hot-apply");
  revWrap.appendChild(revLabel); revWrap.appendChild(revPair); revWrap.appendChild(revHint);
  uiCard.appendChild(revWrap);
  formPanel.appendChild(uiCard);

  // [daemon] section
  const daemonCard = cfgFormCard("daemon");

  // Idle timeout: two separate number fields (minutes + seconds).
  // Parses the stored Go duration string (e.g. "15m0s", "1h30m0s", "0s")
  // into total minutes and remaining seconds, then reassembles on change.
  const parsedIdle = parseDurationToMins(cfgState.idleTimeout || "0s");
  const idleWrap = el("div", "cfg-form-row");
  const idleLabel = el("span", "cfg-field-label"); idleLabel.textContent = "idle timeout";
  const idlePair = el("div", "cfg-idle-pair");
  const idleMinsIn = el("input", "input mono cfg-idle-num");
  idleMinsIn.type = "number"; idleMinsIn.min = "0"; idleMinsIn.step = "1";
  idleMinsIn.value = String(parsedIdle.mins);
  idleMinsIn.placeholder = "0";
  idleMinsIn.autocomplete = "off";
  idleMinsIn.title = "minutes";
  idlePair.appendChild(idleMinsIn);
  idlePair.appendChild(el("span", "cfg-idle-unit", "m"));
  const idleSecsIn = el("input", "input mono cfg-idle-num");
  idleSecsIn.type = "number"; idleSecsIn.min = "0"; idleSecsIn.max = "59"; idleSecsIn.step = "1";
  idleSecsIn.value = String(parsedIdle.secs);
  idleSecsIn.placeholder = "0";
  idleSecsIn.autocomplete = "off";
  idleSecsIn.title = "seconds";
  idlePair.appendChild(idleSecsIn);
  idlePair.appendChild(el("span", "cfg-idle-unit", "s"));
  const updateIdleTimeout = () => {
    const m = Math.max(0, parseInt(idleMinsIn.value, 10) || 0);
    const s = Math.max(0, Math.min(59, parseInt(idleSecsIn.value, 10) || 0));
    cfgState.idleTimeout = serializeDuration(m, s);
  };
  idleMinsIn.oninput = updateIdleTimeout;
  idleSecsIn.oninput = updateIdleTimeout;
  // Initialize cfgState.idleTimeout from the parsed fields.
  updateIdleTimeout();
  const idleHint = el("span", "cfg-field-hint", "both 0 = disabled · hot-apply");
  idleWrap.appendChild(idleLabel); idleWrap.appendChild(idlePair); idleWrap.appendChild(idleHint);
  daemonCard.appendChild(idleWrap);
  formPanel.appendChild(daemonCard);

  // [security] section
  const secCard = cfgFormCard("security");

  // session_ttl — Go duration string (12h default; "0s" = no absolute cap).
  const sttlWrap = el("div", "cfg-form-row");
  const sttlLabel = el("label", "cfg-field-label"); sttlLabel.textContent = "session ttl";
  const sttlIn = el("input", "input mono cfg-port-input");
  sttlIn.type = "text"; sttlIn.value = cfgState.sessionTTL || "12h0m0s";
  sttlIn.placeholder = "12h"; sttlIn.autocomplete = "off"; sttlIn.spellcheck = false;
  sttlIn.oninput = () => { cfgState.sessionTTL = sttlIn.value.trim(); };
  sttlLabel.appendChild(sttlIn);
  const sttlHint = el("span", "cfg-field-hint", "absolute session lifetime (e.g. 12h); 0s = no cap · hot-apply");
  sttlWrap.appendChild(sttlLabel); sttlWrap.appendChild(sttlHint);
  secCard.appendChild(sttlWrap);

  // session_idle — Go duration string ("0s" = inherit [daemon] idle_timeout).
  const sidleWrap = el("div", "cfg-form-row");
  const sidleLabel = el("label", "cfg-field-label"); sidleLabel.textContent = "session idle";
  const sidleIn = el("input", "input mono cfg-port-input");
  sidleIn.type = "text"; sidleIn.value = cfgState.sessionIdle || "0s";
  sidleIn.placeholder = "0s"; sidleIn.autocomplete = "off"; sidleIn.spellcheck = false;
  sidleIn.oninput = () => { cfgState.sessionIdle = sidleIn.value.trim(); };
  sidleLabel.appendChild(sidleIn);
  const sidleHint = el("span", "cfg-field-hint", "sliding idle window; 0s = inherit idle_timeout · hot-apply");
  sidleWrap.appendChild(sidleLabel); sidleWrap.appendChild(sidleHint);
  secCard.appendChild(sidleWrap);

  // privsep — checkbox + a loud warning (enabling needs provisioning + restart).
  const psRow = el("label", "cfg-form-row");
  const psCb = el("input"); psCb.type = "checkbox"; psCb.checked = !!cfgState.privsep;
  const psWarn = el("div", "studio-warn");
  const updatePsWarn = () => { psWarn.hidden = !psCb.checked; };
  psCb.onchange = () => { cfgState.privsep = psCb.checked; updatePsWarn(); };
  psRow.appendChild(psCb); psRow.appendChild(el("span", null, "privsep"));
  psRow.appendChild(el("span", "cfg-field-hint", "run trusted-.byn exec children as the _byn-exec user"));
  secCard.appendChild(psRow);
  psWarn.textContent = "Requires `sudo byn setup` provisioning and a daemon restart to take effect. Enabled without provisioning, byn exec fails closed with a setup hint.";
  updatePsWarn();
  secCard.appendChild(psWarn);

  formPanel.appendChild(secCard);

  formPanel.hidden = cfgState.rawMode;
  box.appendChild(formPanel);

  // ── Raw textarea panel ─────────────────────────────────────────────────────
  const rawPanel = el("div", "cfg-raw-panel");
  cfgState.rawPanel = rawPanel;

  const ta = el("textarea", "input mono cfg-editor");
  ta.value = cfgState.rawContent;
  ta.rows = 18;
  ta.spellcheck = false;
  ta.autocomplete = "off";
  ta.autocapitalize = "off";
  ta.oninput = () => { cfgState.rawContent = ta.value; };
  cfgState.rawTA = ta;
  rawPanel.appendChild(ta);

  rawPanel.hidden = !cfgState.rawMode;
  box.appendChild(rawPanel);

  // ── Inline status panel + save button ─────────────────────────────────────
  const notesEl = el("div", "cfg-notes"); notesEl.hidden = true;
  cfgState.notesEl = notesEl;
  box.appendChild(notesEl);

  const saveBtn = el("button", "btn btn-primary sm cfg-save", "save config");
  cfgState.saveBtn = saveBtn;
  box.appendChild(saveBtn);

  saveBtn.onclick = saveCfg;

  // ── Daemon control card ──────────────────────────────────────────────────
  // Reload config in-place (no restart, no vault disruption) and Restart
  // (graceful shutdown; auto-start or `byn start` brings it back).
  const cfgCtrlCard = cfgFormCard("daemon");
  const cfgPathEl = el("div", "cfg-daemon-path");
  cfgPathEl.appendChild(el("span", "cfg-path-label", "config"));
  const cfgPathMono = el("span", "cfg-path mono");
  cfgPathMono.textContent = configPath;
  cfgPathMono.title = configPath;
  cfgPathEl.appendChild(cfgPathMono);
  cfgCtrlCard.appendChild(cfgPathEl);

  // Inline notes panel for daemon card feedback.
  const daemonNotes = el("div", "cfg-notes"); daemonNotes.hidden = true;
  cfgCtrlCard.appendChild(daemonNotes);

  const daemonBtns = el("div", "cfg-daemon-btns");

  const reloadBtn = el("button", "btn btn-ghost sm", "reload config");
  reloadBtn.title = "Hot-apply config changes without restarting the daemon (same as SIGHUP / `byn daemon reload`)";
  reloadBtn.onclick = async () => {
    reloadBtn.disabled = true;
    restartBtn.disabled = true;
    reloadBtn.textContent = "reloading…";
    daemonNotes.hidden = true;
    try {
      const resp = await api("POST", "/api/daemon/reload", {});
      const notes = resp.change_notes || [];
      showConfigNotes(daemonNotes, notes.length ? notes : ["no config changes"], false);
    } catch (e) {
      showConfigNotes(daemonNotes, ["reload failed: " + e.message], true);
    } finally {
      reloadBtn.disabled = false;
      restartBtn.disabled = false;
      reloadBtn.textContent = "reload config";
    }
  };
  daemonBtns.appendChild(reloadBtn);

  const restartBtn = el("button", "btn btn-ghost sm cfg-restart-btn", "restart daemon");
  restartBtn.title = "Graceful shutdown — the portal will disconnect; auto-start or `byn start` relaunches the daemon";
  restartBtn.onclick = async () => {
    const confirmed = await openDialog({
      title: "Restart daemon?",
      message: "The daemon will stop gracefully. The portal will disconnect.\n\nAuto-start (launchd/systemd) will relaunch it automatically, or run `byn start` to restart manually.",
      okText: "restart",
    });
    if (!confirmed) return;
    reloadBtn.disabled = true;
    restartBtn.disabled = true;
    restartBtn.textContent = "stopping…";
    daemonNotes.hidden = true;
    try {
      await api("POST", "/api/daemon/restart", {});
    } catch (_) {
      // The daemon may have closed the connection before we read the response.
    }
    // Poll /api/status until the daemon comes back (or 60s timeout).
    showConfigNotes(daemonNotes, ["daemon stopped — waiting for restart…"], false);
    restartBtn.textContent = "waiting for daemon…";
    const deadline = Date.now() + 60000;
    const poll = async () => {
      if (Date.now() > deadline) {
        showConfigNotes(daemonNotes, ["daemon did not come back within 60s — run `byn start` to restart manually"], true);
        restartBtn.disabled = false;
        restartBtn.textContent = "restart daemon";
        return;
      }
      try {
        await api("GET", "/api/status");
        // Daemon is back.
        showConfigNotes(daemonNotes, ["daemon restarted"], false);
        reloadBtn.disabled = false;
        restartBtn.disabled = false;
        restartBtn.textContent = "restart daemon";
      } catch (_) {
        setTimeout(poll, 500);
      }
    };
    setTimeout(poll, 300);
  };
  daemonBtns.appendChild(restartBtn);
  cfgCtrlCard.appendChild(daemonBtns);
  box.appendChild(cfgCtrlCard);
}

// cfgFormCard returns a titled section card for the visual config form.
function cfgFormCard(title) {
  const card = el("div", "cfg-form-card");
  card.appendChild(el("div", "cfg-form-card-head", title));
  return card;
}

// parseDurationToMins parses a Go duration string (e.g. "15m0s", "1h30m5s",
// "45s", "0s") into { mins, secs } where mins is the total minutes (including
// hours folded in) and secs is the remaining seconds (0–59).
// Unknown or unparseable strings map to { mins: 0, secs: 0 }.
// Sub-second values (e.g. "500ms") are rounded UP to 1s so the form does not
// silently display them as "disabled" (0m 0s). The daemon accepts 1s fine.
function parseDurationToMins(d) {
  if (!d || d === "0" || d === "0s") return { mins: 0, secs: 0 };
  // Sub-second only (e.g. "500ms", "250ms") → round up to 1s.
  if (/^\d+ms$/.test(d)) return { mins: 0, secs: 1 };
  // Matches any sequence of: optional hours (Nh), optional minutes (Nm), optional seconds (Ns).
  const m = d.match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?$/);
  if (!m) return { mins: 0, secs: 0 };
  const h = parseInt(m[1] || "0", 10);
  const min = parseInt(m[2] || "0", 10);
  const sec = Math.round(parseFloat(m[3] || "0"));
  return { mins: h * 60 + min, secs: sec };
}

// serializeDuration converts mins (total) + secs (0–59) into a Go duration
// string suitable for the config parser: "MmSs" normally, "0s" when both zero.
function serializeDuration(mins, secs) {
  mins = Math.max(0, mins || 0);
  secs = Math.max(0, Math.min(59, secs || 0));
  if (mins === 0 && secs === 0) return "0s";
  let out = "";
  if (mins > 0) out += mins + "m";
  out += secs + "s";
  return out;
}

// serializeCfg builds the TOML content from the current cfgState visual-form
// values. Only the known keys are emitted — the strict config parser
// refuses unknown keys, so valid configs can never contain anything else.
// Keys that match the compiled-in defaults are still emitted for clarity
// (the daemon's config.Parse handles them correctly).
//
// DEFAULT FORM VALUES (keep in sync with TestSerializeCfgDefaultForm in
// internal/config/config_test.go — that test feeds these exact bytes to
// config.Parse to guard serializer drift):
//   uiEnabled=true, uiPort=2967, revealHideAfter="15s", idleTimeout="15m0s"
function serializeCfg(st) {
  const lines = [];
  lines.push("[ui]");
  lines.push("enabled = " + (st.uiEnabled ? "true" : "false"));
  lines.push("port    = " + String(st.uiPort || 2967));
  lines.push("reveal_hide_after = " + tomlStr(st.revealHideAfter || "15s"));
  lines.push("");
  lines.push("[daemon]");
  lines.push("idle_timeout = " + tomlStr(st.idleTimeout || "0s"));
  lines.push("");
  lines.push("[security]");
  lines.push("session_ttl  = " + tomlStr(st.sessionTTL || "12h0m0s"));
  lines.push("session_idle = " + tomlStr(st.sessionIdle || "0s"));
  // privsep is presence-detecting (absent ⇒ off): only emit when enabled so the
  // default form stays clean. Enabling it needs `sudo byn setup` provisioning.
  if (st.privsep) lines.push("privsep = true");
  lines.push("");
  return lines.join("\n");
}

// toggleCfgMode switches the settings panel between form and raw modes.
// Rule: switching NEVER discards or re-fetches — it carries the values
// currently entered in the browser. Reset is the ONLY way back to saved state.
//   form → raw: seeds the textarea from the serialized form state.
//   raw  → form: validates the CURRENT textarea content via config.validate;
//     errors → stay raw + show inline error (no modal, nothing discarded);
//     success → populate cfgState from resp.parsed and switch.
async function toggleCfgMode() {
  if (!cfgState) return;
  if (!cfgState.rawMode) {
    // form → raw: seed textarea from current form values.
    const content = serializeCfg(cfgState);
    cfgState.rawMode = true;
    cfgState.rawContent = content;
    if (cfgState.rawTA)  cfgState.rawTA.value = content;
    if (cfgState.rawPanel)  cfgState.rawPanel.hidden  = false;
    if (cfgState.formPanel) cfgState.formPanel.hidden = true;
    if (cfgState.modeToggle) {
      cfgState.modeToggle.textContent    = "switch to form";
      cfgState.modeToggle.dataset.mode   = "raw";
    }
  } else {
    // raw → form: validate the CURRENT textarea content via config.validate.
    // Errors → stay raw, show inline error (nothing is discarded, nothing lost).
    // Success → carry the parsed values into cfgState form fields and switch.
    const rawContent = cfgState.rawContent || "";
    let validateResp;
    try {
      validateResp = await api("POST", "/api/config/validate", { content: rawContent });
    } catch (e) {
      if (cfgState.notesEl) {
        showConfigNotes(cfgState.notesEl, ["could not validate config: " + e.message], true);
      }
      return;
    }
    const errors = (validateResp && validateResp.errors) || [];
    if (errors.length > 0) {
      // Stay in raw mode; show inline error — the user must fix it or press Reset.
      const msg = "cannot switch to form: " + (errors[0].message || "invalid config") +
        " — fix the error, or use Reset to reload the saved file, then switch";
      if (cfgState.notesEl) showConfigNotes(cfgState.notesEl, [msg], true);
      return;
    }
    // Zero errors — carry the parsed values through to cfgState form fields.
    const p = validateResp && validateResp.parsed;
    if (p) {
      cfgState.uiEnabled       = p.ui_enabled;
      cfgState.uiPort          = p.ui_port;
      cfgState.revealHideAfter = p.reveal_hide_after;
      cfgState.idleTimeout     = p.idle_timeout;
      cfgState.sessionTTL      = p.session_ttl;
      cfgState.sessionIdle     = p.session_idle;
      cfgState.privsep         = p.privsep === true;
    }
    cfgState.rawMode = false;
    if (cfgState.rawPanel)  cfgState.rawPanel.hidden  = true;
    if (cfgState.formPanel) {
      cfgState.formPanel.hidden = false;
      // Re-render the form to reflect the newly carried values.
      renderSettingsView();
    }
    if (cfgState.modeToggle) {
      cfgState.modeToggle.textContent  = "switch to raw";
      cfgState.modeToggle.dataset.mode = "form";
    }
  }
}

// saveCfg is the save button handler for both form and raw modes.
async function saveCfg() {
  if (!cfgState) return;
  const notesEl = cfgState.notesEl;
  const saveBtn = cfgState.saveBtn;

  // Validate port before building TOML (form mode only).
  if (!cfgState.rawMode && (cfgState.uiPort === null || cfgState.uiPort === undefined)) {
    showConfigNotes(notesEl, ["port must be a number between 1 and 65535"], true);
    return;
  }

  // Build the TOML to send.
  const newContent = cfgState.rawMode
    ? (cfgState.rawContent || "")
    : serializeCfg(cfgState);

  if (notesEl) { notesEl.hidden = true; notesEl.textContent = ""; }
  if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = "saving…"; }

  try {
    const resp = await apiWithAuth("POST", "/api/config", { content: newContent }, "");
    // Update dirty-tracking baseline so the guard does not fire after a clean save.
    cfgBaseline = newContent;
    // Refresh the cached reveal auto-hide timeout from the authoritative saved
    // config (covers raw-mode edits where cfgState.revealHideAfter is stale).
    loadRevealHideConfig();
    showConfigNotes(notesEl, resp.change_notes || [], false);
    toast("config saved");
  } catch (e) {
    showConfigNotes(notesEl, [e.message], true);
  } finally {
    if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = "save config"; }
  }
}

// showConfigNotes renders change_notes (or error messages) in the notes panel.
function showConfigNotes(panel, notes, isError) {
  panel.textContent = "";
  panel.className = "cfg-notes " + (isError ? "cfg-notes-error" : "cfg-notes-ok");
  panel.hidden = notes.length === 0;
  if (!notes.length) return;
  const title = el("div", "cfg-notes-title", isError ? "error" : "applied changes");
  panel.appendChild(title);
  const list = el("ul", "cfg-notes-list");
  for (const n of notes) {
    const li = el("li");
    li.textContent = n;
    list.appendChild(li);
  }
  panel.appendChild(list);
}

async function renderProjectsView() {
  const box = $("#content-body"); box.innerHTML = "";
  if (!state.scope.vault) { box.appendChild(emptyHint("pick a vault")); return; }
  const data = await api("GET", "/api/projects?vault=" + enc(state.scope.vault));
  const list = el("div", "browse");
  list.appendChild(el("div", "browse-head", "projects in " + state.scope.vault));
  for (const p of data.projects || []) {
    const it = el("button", "browse-item");
    it.appendChild(el("span", "lvl lvl-project", "p"));
    it.appendChild(el("span", "browse-name", p.name));
    if (defaultish(p.name)) it.appendChild(el("span", "tag-default", "default"));
    it.appendChild(el("span", "browse-go", "envs ›"));
    it.onclick = () => navProject(state.scope.vault, p.name);
    list.appendChild(it);
  }
  list.appendChild(manageRow("new project…", createProject));
  box.appendChild(list);
}
async function renderEnvsView() {
  const box = $("#content-body"); box.innerHTML = "";
  const data = await api("GET", "/api/envs?vault=" + enc(state.scope.vault) + "&project=" + enc(state.scope.project));
  const list = el("div", "browse");
  list.appendChild(el("div", "browse-head", "envs in " + state.scope.vault + " › " + state.scope.project));
  for (const en of data.envs || []) {
    const it = el("button", "browse-item");
    it.appendChild(el("span", "lvl lvl-env", "e"));
    it.appendChild(el("span", "browse-name", en.name));
    if (en.is_default) it.appendChild(el("span", "tag-default", "default"));
    it.appendChild(el("span", "browse-go", "open ›"));
    it.onclick = () => selectScope(state.scope.vault, state.scope.project, en.name);
    list.appendChild(it);
  }
  list.appendChild(manageRow("new env…", createEnv));
  box.appendChild(list);
}
function emptyHint(text) { const e = el("div", "empty"); e.appendChild(el("span", "big", text)); return e; }

// ---- entries ------------------------------------------------------------

function scopeQuery(env) {
  const s = state.scope, e = env !== undefined ? env : s.env;
  return `vault=${enc(s.vault)}&project=${enc(s.project)}&env=${enc(e)}`;
}
function curScope() { return { vault: state.scope.vault, project: state.scope.project, env: state.scope.env }; }

// ---- import / export ----------------------------------------------------

// exportEnv reveals every value in the active env and downloads it as a .env
// file. Each reveal is a real `get` (audited); requires the vault unlocked.
async function exportEnv() {
  const s = state.scope;
  if (!s.env) { toast("pick an env first", true); return; }
  if (vaultLocked(s.vault)) { toast("unlock the vault to export values", true); return; }
  if (!state.entries.length) { toast("nothing to export", true); return; }
  const lines = [];
  for (const e of state.entries) {
    try {
      // Portal export: presence tokens are single-use, so each entry here re-triggers
      // the passkey/password step-up via apiWithAuth. Batch authorization (one step-up
      // covers all entries) lands with session tokens in NU-3.
      const r = await apiWithAuth("POST", "/api/entry/reveal", { scope: curScope(), name: e.name }, s.vault);
      lines.push(dotenvLine(e.name, r.value));
    } catch (err) { toast(`export failed at ${e.name}: ${err.message}`, true); return; }
  }
  downloadText(`${s.vault}.${s.project}.${s.env}.env`, lines.join("\n") + "\n");
  toast(`exported ${lines.length} vars`);
}
function dotenvLine(k, v) {
  v = v == null ? "" : String(v);
  if (v === "" || /[\s"'#=$`\\]/.test(v)) return `${k}="${v.replace(/([\\"$`])/g, "\\$1")}"`;
  return `${k}=${v}`;
}
function downloadText(name, text) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

// importEnv pastes KEY=value lines into the active env (existing keys are
// overwritten). Requires the vault unlocked (writes need the key). Offers
// both a text-paste dialog and a "browse…" button that opens the daemon-backed
// file picker and reads the picked file via /api/fs/readfile.
async function importEnv() {
  const s = state.scope;
  if (!s.env) { toast("pick an env first", true); return; }
  if (vaultLocked(s.vault)) { toast("unlock the vault to import", true); return; }
  // Use a custom import dialog that includes a browse button wired to the textarea.
  const text = await openImportDialog(s.vault, s.project, s.env);
  if (!text || !text.trim()) return;
  await applyImport(parseDotenv(text));
}

// openImportDialog opens a custom import dialog with a textarea and a "browse…"
// button. The browse button opens the file picker (files + dirs) and populates
// the textarea with the picked file's content via /api/fs/readfile. Returns the
// textarea text on confirm, or null on cancel.
function openImportDialog(vault, project, env) {
  return new Promise((resolve) => {
    const dlg = $("#dialog"), title = $("#dialog-title"), msg = $("#dialog-msg");
    const box = $("#dialog-fields"), err = $("#dialog-error"), ok = $("#dialog-ok"), cancel = $("#dialog-cancel");
    let done = false;

    title.textContent = "Import .env";
    msg.textContent = `Paste KEY=value lines into ${vault}/${project}/${env}. Existing keys are overwritten. Use "browse…" to load from a file.`;
    msg.hidden = false;
    ok.textContent = "import";
    ok.classList.toggle("btn-danger", false);
    ok.classList.toggle("btn-primary", true);
    err.textContent = "";
    box.innerHTML = "";
    box.hidden = false;

    // Textarea field.
    const wrap = el("label", "field");
    wrap.appendChild(el("span", "field-label", "env text"));
    const ta = el("textarea", "input mono area");
    ta.placeholder = "API_KEY=sk-...\nDB_URL=postgres://...";
    ta.value = "";
    ta.autocomplete = "off"; ta.spellcheck = false; ta.autocapitalize = "off";
    ta.rows = 8;
    wrap.appendChild(ta);
    box.appendChild(wrap);

    // Browse row.
    const browseRow = el("div", "field import-browse-row");
    const browseBtn = el("button", "btn btn-ghost sm", "browse…");
    browseBtn.type = "button";
    browseBtn.title = "pick a .env or other text file";
    browseBtn.onclick = async () => {
      const filePath = await pickFilePath("");
      if (!filePath) return;
      try {
        const d = await api("GET", "/api/fs/readfile?path=" + enc(filePath));
        if (d && d.content !== undefined) {
          ta.value = d.content;
          err.textContent = "";
        }
      } catch (e) { err.textContent = "cannot read file: " + e.message; }
    };
    browseRow.appendChild(browseBtn);
    box.appendChild(browseRow);

    dlg.hidden = false;
    setTimeout(() => { ta.focus(); }, 30);

    function cleanup() { dlg.hidden = true; ok.onclick = cancel.onclick = null; document.removeEventListener("keydown", onKey, true); }
    function finish(v) { if (done) return; done = true; cleanup(); resolve(v); }
    function submit() { finish(ta.value); }
    function dismiss() { finish(null); }
    function onKey(e) { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); dismiss(); } }
    ok.onclick = submit; cancel.onclick = dismiss;
    document.addEventListener("keydown", onKey, true);
  });
}
async function applyImport(pairs) {
  if (!pairs.length) { toast("no KEY=value lines found", true); return; }
  let ok = 0;
  for (const [k, v] of pairs) {
    try { await apiWithAuth("POST", "/api/entries", { scope: curScope(), name: k, value: v }, state.scope.vault); ok++; }
    catch (err) { toast(`import failed at ${k}: ${err.message}`, true); break; }
  }
  toast(`imported ${ok}/${pairs.length} vars`);
  await loadEntries();
}
// parseDotenv parses KEY=value lines: ignores blanks/#comments, strips an
// optional `export ` prefix, and unquotes single/double-quoted values.
function parseDotenv(text) {
  const out = [];
  for (let line of text.split("\n")) {
    line = line.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("export ")) line = line.slice(7).trim();
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const k = line.slice(0, eq).trim();
    let v = line.slice(eq + 1).trim();
    if (v.length >= 2 && ((v[0] === '"' && v.endsWith('"')) || (v[0] === "'" && v.endsWith("'")))) {
      const dq = v[0] === '"';
      v = v.slice(1, -1);
      if (dq) v = v.replace(/\\n/g, "\n").replace(/\\(["\\$`])/g, "$1");
    }
    out.push([k, v]);
  }
  return out;
}

async function loadEntries() {
  state.view = "entries"; renderCrumbs();
  try {
    const data = await api("GET", "/api/entries?" + scopeQuery());
    state.entries = data.secrets || [];
    state.defaultNames = new Set();
    if (state.scope.env && !defaultish(state.scope.env)) {
      try { const def = await api("GET", "/api/entries?" + scopeQuery("default")); for (const s of def.secrets || []) state.defaultNames.add(s.name); } catch (_) {}
    }
    renderEntries();
  } catch (e) {
    const box = $("#content-body"); box.innerHTML = "";
    if (/locked/i.test(e.message)) {
      const p = el("div", "locked-pane");
      p.appendChild(el("div", "lk", "🔒"));
      p.appendChild(el("p", null, `“${state.scope.vault}” is locked — values are hidden.`));
      const btn = el("button", "btn btn-ghost sm", "unlock vault");
      btn.onclick = () => unlockVault(state.scope.vault);
      p.appendChild(btn); box.appendChild(p);
    } else { toast(e.message, true); }
  }
}

function badgeFor(s) {
  if (!state.scope.env || defaultish(state.scope.env)) return null;
  if (s.source === "default") return { glyph: "↓", cls: "bdg-inherit" };
  if (state.defaultNames.has(s.name)) return { glyph: "⤴", cls: "bdg-override" };
  return { glyph: "✦", cls: "bdg-new" };
}

function renderEntries() {
  const box = $("#content-body"); box.innerHTML = "";
  // Value cells are recreated on each render — reset the reveal-all registry
  // and drop pending mask timers (the fresh rows start masked).
  state.revealCells = {};
  state.revealAllBtn = null;
  for (const t of Object.keys(state.revealTimers)) clearTimeout(state.revealTimers[t]);
  state.revealTimers = {};
  if (vaultLocked(state.scope.vault)) {
    const b = el("div", "locked-banner");
    b.appendChild(el("span", null, "🔒 unlock vault to see values"));
    const u = el("button", "btn btn-ghost sm", "unlock");
    u.onclick = () => unlockVault(state.scope.vault);
    b.appendChild(u);
    box.appendChild(b);
  } else if (state.scope.env) {
    const bar = el("div", "entry-tools");
    const revealAll = el("button", "btn btn-ghost sm", "reveal all");
    revealAll.title = "reveal every value in this env (R) · click a value to reveal just one";
    revealAll.onclick = entriesToggleRevealAll;
    state.revealAllBtn = revealAll;
    const imp = el("button", "btn btn-ghost sm", "import");
    imp.title = "import KEY=value lines (or drag a .env file here)"; imp.onclick = importEnv;
    const exp = el("button", "btn btn-ghost sm", "export");
    exp.title = "download this env as a .env file"; exp.onclick = exportEnv;
    bar.appendChild(revealAll); bar.appendChild(imp); bar.appendChild(exp);
    // Reset-to-default only for a non-default (inheriting) env.
    if (state.scope.env !== "default") {
      const reset = el("button", "btn btn-ghost sm", "reset to default");
      reset.title = "remove all overrides + added vars in this env (it will inherit default)";
      reset.onclick = resetEnvToDefault;
      bar.appendChild(reset);
    }
    box.appendChild(bar);
  }
  const tbl = el("div", "tbl");
  const head = el("div", "tbl-head");
  head.appendChild(el("span", "", "")); head.appendChild(el("span", "", "KEY"));
  head.appendChild(el("span", "", "VALUE")); head.appendChild(el("span", "", ""));
  tbl.appendChild(head);

  let rows = state.entries;
  if (state.filter) { const f = state.filter.toLowerCase(); rows = rows.filter((s) => s.name.toLowerCase().includes(f)); }
  rows.forEach((s, i) => tbl.appendChild(entryRow(s, i)));
  box.appendChild(tbl);

  if (!rows.length) {
    const e = el("div", "empty");
    e.appendChild(el("span", "big", state.entries.length ? "no matches" : "no env-vars in this scope"));
    e.appendChild(document.createTextNode(state.entries.length ? "clear the search to see all" : "press “+ new” or double-click here to add one"));
    box.appendChild(e);
  }
}
function entryRow(s, i) {
  const inherited = s.source === "default";
  const bd = badgeFor(s);
  // state class colors the key to match the badge (amber override / green new)
  let cls = "trow" + (inherited ? " inherited" : "");
  if (!inherited && bd) cls += bd.cls === "bdg-override" ? " s-override" : (bd.cls === "bdg-new" ? " s-new" : "");
  const row = el("div", cls);
  row.style.animationDelay = Math.min(i * 14, 280) + "ms";

  // Badge cell: inheritance badge + optional empty-value indicator.
  const bdgWrap = el("span", "bdg-wrap");
  bdgWrap.appendChild(el("span", "bdg" + (bd ? " " + bd.cls : ""), bd ? bd.glyph : ""));
  // s.empty is true when the vault is unlocked and the value is the empty string.
  // Show the hollow badge alongside any inheritance badge (both can be present
  // when e.g. an override with an empty value exists in this env).
  if (s.empty === true) {
    const emptyBdg = el("span", "bdg bdg-empty", "○");
    emptyBdg.title = "empty value";
    bdgWrap.appendChild(emptyBdg);
  }
  row.appendChild(bdgWrap);

  const name = el("span", "cell name", s.name);
  if (!inherited) { name.title = "double-click to rename"; name.ondblclick = (e) => { e.stopPropagation(); editName(s, name); }; }
  else { name.title = "inherited from default"; }
  row.appendChild(name);
  const val = el("span", "cell val"); val.appendChild(maskDots());
  state.revealCells[s.name] = val; // for reveal-all in the entries view
  // Editing an inherited var writes an OVERRIDE into the current env
  // (put targets the exact scope — it does not touch the default).
  val.title = inherited ? "click to reveal · double-click to override" : "click to reveal · double-click to edit";
  // Single click reveals (toggle); double click edits. A short timer
  // distinguishes the two so a double-click doesn't also reveal.
  let ct = null;
  val.onclick = () => { if (ct) return; ct = setTimeout(() => { ct = null; toggleReveal(s, val); }, 200); };
  val.ondblclick = (e) => { e.stopPropagation(); if (ct) { clearTimeout(ct); ct = null; } editValue(s, val); };
  row.appendChild(val);
  const acts = el("span", "acts");
  acts.appendChild(iconBtn("eye", "reveal", "reveal value", () => reveal(s, val)));
  acts.appendChild(iconBtn("copy", "copy", "copy value", () => copyValue(s)));
  acts.appendChild(iconBtn("pencil", "edit", inherited ? "override in this env" : "edit value", () => editValue(s, val)));
  // Action set depends on the row's inheritance state (bd is null in the
  // default env, where every row is just deletable; see badgeFor):
  //   override (⤴) → revert (drop override → default) + persist (set as default)
  //   new (✦)      → delete + persist (promote to default, available to all envs)
  //   inherited (↓)→ no destructive/promote action (edit overrides in place)
  //   default env  → delete (unchanged)
  if (bd && bd.cls === "bdg-override") {
    acts.appendChild(iconBtn("revert", "revert", "revert to the default value", () => revertOverride(s)));
    acts.appendChild(iconBtn("persist", "persist", "set this value as the default (all envs)", () => persistToDefault(s)));
  } else if (bd && bd.cls === "bdg-new") {
    acts.appendChild(iconBtn("trash", "danger", "delete", () => doDelete(s)));
    acts.appendChild(iconBtn("persist", "persist", "save this value to default (all envs)", () => persistToDefault(s)));
  } else if (!inherited) {
    acts.appendChild(iconBtn("trash", "danger", "delete", () => doDelete(s)));
  }
  row.appendChild(acts);
  return row;
}
function maskDots() { return el("span", "mask", "•••••••••"); }

// ---- reveal auto-hide timeout (configurable: [ui] reveal_hide_after) ------

// revealHideAfterMs is how long a revealed secret stays visible before
// re-masking, mirroring [ui] reveal_hide_after from ~/.byn/config. 0 = never
// auto-hide (stays until manually hidden / the studio closes). Cached on boot
// and refreshed when settings load/save; defaults to 15s until loaded.
let revealHideAfterMs = 15000;

// goDurationMs parses a Go duration string ("15s", "1m30s", "500ms", "0s")
// into milliseconds, or null when unparseable.
function goDurationMs(str) {
  if (!str) return null;
  const re = /(\d+(?:\.\d+)?)(ms|s|m|h)/g;
  const unit = { ms: 1, s: 1000, m: 60000, h: 3600000 };
  let total = 0, matched = false, m;
  while ((m = re.exec(str)) !== null) { matched = true; total += parseFloat(m[1]) * unit[m[2]]; }
  return matched ? total : null;
}

// setRevealHideAfter updates the cached timeout from a Go duration string,
// ignoring unparseable input (keeps the previous value).
function setRevealHideAfter(durStr) {
  const ms = goDurationMs(durStr);
  if (ms !== null) revealHideAfterMs = ms;
}

// loadRevealHideConfig fetches the config once (non-blocking) to seed the
// cached reveal timeout. Failures are silent — the default stands.
async function loadRevealHideConfig() {
  try {
    const d = await api("GET", "/api/config");
    if (d && d.parsed && d.parsed.reveal_hide_after) setRevealHideAfter(d.parsed.reveal_hide_after);
  } catch (_) { /* keep default */ }
}

async function revealValue(s) {
  const env = s.source === "default" ? "default" : state.scope.env;
  const data = await apiWithAuth("POST", "/api/entry/reveal",
    { scope: { vault: state.scope.vault, project: state.scope.project, env }, name: s.name },
    state.scope.vault);
  return data.value;
}
async function reveal(s, valEl) {
  if (vaultLocked(state.scope.vault)) {
    // A value cannot be decrypted while the vault is locked: a one-shot password
    // can authorize the read but does not load the vault key, so the daemon
    // returns "vault is locked". Unlock the vault first — that loads the key for
    // this session — then values reveal normally (no per-value password prompt).
    await unlockVault(state.scope.vault);
    return;
  }
  try {
    const value = await revealValue(s);
    valEl.classList.add("revealed"); valEl.textContent = value;
    clearTimeout(state.revealTimers[s.name]);
    if (revealHideAfterMs > 0) {
      state.revealTimers[s.name] = setTimeout(() => hideReveal(s, valEl), revealHideAfterMs);
    }
  } catch (e) { toast(e.message, true); }
}
function hideReveal(s, valEl) {
  clearTimeout(state.revealTimers[s.name]);
  valEl.classList.remove("revealed"); valEl.innerHTML = ""; valEl.appendChild(maskDots());
}
function toggleReveal(s, valEl) {
  if (valEl.classList.contains("revealed")) hideReveal(s, valEl); else reveal(s, valEl);
}
async function copyValue(s) {
  if (vaultLocked(state.scope.vault)) { await unlockVault(state.scope.vault); return; }
  try { const value = await revealValue(s); await navigator.clipboard.writeText(value); toast("copied " + s.name); }
  catch (e) { toast(e.message || "copy failed", true); }
}

// revealManyValues fetches plaintext for a list of { scope, name } requests
// with ONE up-front authorization: a password is reused across reads; a
// single-use passkey token covers one read, so the rest re-prompt (same as
// the .env export). Calls onValue(req, value) for each success. Returns true
// when complete, false on cancel / locked / failure (with a toast). Each
// read is an audited `get`.
async function revealManyValues(reqs, vault, onValue) {
  let creds = null; // reusable password; passkey tokens are single-use
  for (const req of reqs) {
    const base = { scope: req.scope, name: req.name };
    if (creds && creds.password) base.password = creds.password;
    let data;
    try {
      data = await api("POST", "/api/entry/reveal", base);
    } catch (e) {
      if (e.code !== "auth_required") { toast(e.message || ("could not reveal " + req.name), true); return false; }
      if (!creds) { creds = await authorizeStepUp(vault); if (!creds) return false; }
      try {
        data = await api("POST", "/api/entry/reveal", Object.assign({}, base, {
          password: creds.password || "", presence_token: creds.presence_token || undefined,
        }));
      } catch (e2) { toast(e2.message || ("could not reveal " + req.name), true); return false; }
      if (creds.presence_token && !creds.password) creds = null;
    }
    onValue(req, data.value);
  }
  return true;
}

// ---- reveal-all + reset, for the entries (env-vars) view ------------------

// entriesAllRevealed is true when every value cell is currently revealed.
function entriesAllRevealed() {
  const names = Object.keys(state.revealCells);
  if (!names.length) return false;
  return names.every((n) => state.revealCells[n].classList.contains("revealed"));
}

// entriesUpdateRevealBtn syncs the toolbar button label.
function entriesUpdateRevealBtn() {
  if (state.revealAllBtn) state.revealAllBtn.textContent = entriesAllRevealed() ? "hide all" : "reveal all";
}

// entriesHideAll re-masks every revealed value.
function entriesHideAll() {
  for (const s of state.entries) {
    const val = state.revealCells[s.name];
    if (val && val.classList.contains("revealed")) hideReveal(s, val);
  }
  entriesUpdateRevealBtn();
}

// entriesToggleRevealAll reveals every value at once (one up-front auth), or
// masks them all if every one is already revealed. Bound to the toolbar button
// and `R`. Single-click on a row still reveals just that one (unchanged).
async function entriesToggleRevealAll() {
  if (state.view !== "entries") return;
  if (vaultLocked(state.scope.vault)) { toast("unlock the vault to reveal values", true); return; }
  const entries = state.entries || [];
  if (!entries.length) return;
  if (entriesAllRevealed()) { entriesHideAll(); return; }
  // Inherited vars read from the default env (mirrors single-row reveal).
  const reqs = entries
    .filter((s) => { const v = state.revealCells[s.name]; return v && !v.classList.contains("revealed"); })
    .map((s) => ({
      s, name: s.name,
      scope: { vault: state.scope.vault, project: state.scope.project, env: s.source === "default" ? "default" : state.scope.env },
    }));
  if (!reqs.length) { entriesUpdateRevealBtn(); return; }
  if (state.revealAllBtn) { state.revealAllBtn.disabled = true; state.revealAllBtn.textContent = "revealing…"; }
  await revealManyValues(reqs, state.scope.vault, (req, v) => {
    const val = state.revealCells[req.name];
    if (!val) return;
    val.classList.add("revealed"); val.textContent = v;
    clearTimeout(state.revealTimers[req.name]);
    if (revealHideAfterMs > 0) state.revealTimers[req.name] = setTimeout(() => hideReveal(req.s, val), revealHideAfterMs);
  });
  if (state.revealAllBtn) state.revealAllBtn.disabled = false;
  entriesUpdateRevealBtn();
}

// resetEnvToDefault removes every override + added var in the current
// (non-default) env, leaving it inheriting default entirely. The default env
// and other envs are untouched. Confirmed via a byn modal; the deletes share
// one authorization (a password is reused; a passkey re-prompts per delete).
async function resetEnvToDefault() {
  const env = state.scope.env;
  if (!env || env === "default") return;
  const own = (state.entries || []).filter((s) => s.source !== "default");
  if (!own.length) { toast("nothing to reset — no overrides or added vars in " + env); return; }
  const locked = vaultLocked(state.scope.vault);
  const o = {
    title: "Reset “" + env + "” to default?",
    danger: true, okText: "reset to default",
    message: "Delete all " + own.length + " override(s) and added var(s) in “" + env +
      "”? It will then inherit the default env entirely. The default env and other envs are untouched. This cannot be undone.",
  };
  if (locked) {
    o.message += "\n\nThis vault is locked — enter the master password to authorize the deletes. The vault stays locked.";
    o.fields = [{ key: "password", label: "master password", type: "password", placeholder: "password",
      validate: (v) => (v ? null : "password required") }];
  }
  const r = await openDialog(o);
  if (!r) return;
  let creds = locked && r.password ? { password: r.password } : null;
  let failed = 0;
  for (const s of own) {
    const base = { scope: curScope(), name: s.name };
    if (creds && creds.password) base.password = creds.password;
    try {
      await api("POST", "/api/entry/delete", base);
    } catch (e) {
      if (e.code !== "auth_required") { failed++; continue; }
      if (!creds) { creds = await authorizeStepUp(state.scope.vault); if (!creds) break; }
      try {
        await api("POST", "/api/entry/delete", Object.assign({}, base, {
          password: creds.password || "", presence_token: creds.presence_token || undefined,
        }));
      } catch (e2) { failed++; }
      if (creds.presence_token && !creds.password) creds = null;
    }
  }
  await loadEntries();
  if (failed) toast(failed + " of " + own.length + " could not be deleted", true);
  else toast("reset “" + env + "” to default — " + own.length + " removed");
}

function editName(s, cell) {
  if (vaultLocked(state.scope.vault)) { toast("unlock the vault to rename", true); return; }
  const input = el("input", "inline-input"); input.value = s.name;
  cell.replaceWith(input); input.focus(); input.select();
  const done = (commit) => async () => {
    const next = input.value.trim();
    if (!commit || !next || next === s.name) { renderEntries(); return; }
    try { await apiWithAuth("POST", "/api/entry/rename", { scope: curScope(), old_name: s.name, new_name: next }, state.scope.vault); toast("renamed → " + next); await loadEntries(); }
    catch (e) { toast(e.message, true); renderEntries(); }
  };
  input.onkeydown = (e) => { if (e.key === "Enter") done(true)(); if (e.key === "Escape") done(false)(); };
  input.onblur = done(false);
}
async function editValue(s, cell) {
  if (vaultLocked(state.scope.vault)) { toast("unlock the vault to edit values", true); return; }
  let current = "";
  try { current = await revealValue(s); } catch (e) { toast(e.message, true); return; }
  const ta = el("textarea", "inline-input mono"); ta.value = current; ta.rows = 1;
  cell.replaceWith(ta); ta.focus(); ta.select(); autoGrow(ta);
  const done = (commit) => async () => {
    if (!commit) { renderEntries(); return; }
    try {
      await apiWithAuth("POST", "/api/entries", { scope: curScope(), name: s.name, value: ta.value }, state.scope.vault);
      toast((s.source === "default" ? "overrode " : "updated ") + s.name + (s.source === "default" ? " in " + state.scope.env : ""));
      await loadEntries();
    } catch (e) { toast(e.message, true); renderEntries(); }
  };
  ta.onkeydown = (e) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { e.preventDefault(); done(true)(); }
    else if (e.key === "Escape") { e.preventDefault(); done(false)(); }
    setTimeout(() => autoGrow(ta), 0);
  };
  ta.onblur = done(false);
}
function addNewRow() {
  if (state.view !== "entries") { toast("pick an env first", true); return; }
  // Writing a value needs the vault key to encrypt — impossible while
  // locked. (Deletes differ: they touch names only, so they accept a
  // one-shot password instead.) Refuse with a clear message.
  if (vaultLocked(state.scope.vault)) { toast("unlock the vault to add values", true); return; }
  state.filter = ""; $("#filter").value = ""; renderEntries();
  const tbl = $(".tbl"); if (!tbl) return;
  const row = el("div", "trow editing");
  row.appendChild(el("span", "bdg", ""));
  const nameIn = el("input", "inline-input"); nameIn.placeholder = "env var name";
  const valIn = el("textarea", "inline-input mono"); valIn.placeholder = "value (⌘↵ to save · multi-line ok)"; valIn.rows = 1;
  row.appendChild(nameIn); row.appendChild(valIn);
  const acts = el("span", "acts");
  const save = el("button", "act save", "save"); const cancel = el("button", "act", "cancel");
  acts.appendChild(save); acts.appendChild(cancel); row.appendChild(acts);
  tbl.appendChild(row); nameIn.focus();
  const commit = async () => {
    const name = nameIn.value.trim(); if (!name) { nameIn.focus(); return; }
    try { await api("POST", "/api/entries", { scope: curScope(), name, value: valIn.value, create_only: true }); toast("added " + name); await loadEntries(); }
    catch (e) { toast(e.message, true); nameIn.focus(); nameIn.select(); }
  };
  const cancelFn = () => renderEntries();
  save.onclick = commit; cancel.onclick = cancelFn;
  nameIn.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); valIn.focus(); } if (e.key === "Escape") cancelFn(); };
  valIn.onkeydown = (e) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { e.preventDefault(); commit(); }
    else if (e.key === "Escape") cancelFn();
    setTimeout(() => autoGrow(valIn), 0);
  };
}
// generateByn opens the .byn studio at /studio (create mode).
function generateByn() {
  navigateGuarded("/studio");
}

// buildPolicyLines returns a short array of human-readable lines describing the
// policy a .byn grants (spec §4.5 footgun guard). Shown in the portal after
// a trust grant so the user sees what they approved.
//
// LOUD warnings are shown for:
//   - any action containing "{{args}}" (permits arbitrary extra arguments)
//   - any action whose first token is a known shell interpreter and has a
//     placeholder (wildcard-equivalent shell injection risk)
function buildPolicyLines(resp) {
  const lines = [];
  // When [auth] exec="none" is set, any command runs re-auth-free on this
  // scope. Show that fact instead of the misleading "every exec requires auth"
  // line (which would be false when exec=none is in effect).
  const execNone = resp.auth && resp.auth["exec"] === "none";
  if (resp.actions_wildcard) {
    lines.push('policy: actions "*" — ALL commands run re-auth-free');
  } else if (resp.actions && resp.actions.length) {
    lines.push("policy: actions: " + resp.actions.join(", "));
    // Per-action LOUD warnings for high-risk patterns.
    const shellInterpreters = new Set(["sh","bash","zsh","dash","ksh","fish","python","python3","node","perl","ruby"]);
    for (const action of resp.actions) {
      if (action === "*") continue;
      // {{args}} tail: permits arbitrary extra arguments.
      if (action.indexOf("{{args}}") !== -1) {
        lines.push('Warning: action "' + action + '" permits ARBITRARY extra arguments');
      }
      // Shell interpreter with placeholder: wildcard-equivalent.
      const tokens = action.split(/\s+/);
      const base = tokens[0] ? tokens[0].replace(/^.*[\\/]/, "") : "";
      const hasPlaceholder = action.indexOf("{{") !== -1;
      if (shellInterpreters.has(base) && hasPlaceholder) {
        lines.push('Warning: action "' + action + '" is wildcard-equivalent — it pins a shell interpreter with a free argument');
      }
    }
  } else if (execNone) {
    lines.push('policy: auth policy exec="none" — ANY command runs re-auth-free on this scope');
  } else {
    lines.push("policy: no [exec] actions — every byn exec will require authorization");
  }
  if (resp.env_wildcard) {
    lines.push('policy: env "*" — ALL scoped vars are injected on exec');
  }
  if (resp.auth && Object.keys(resp.auth).length) {
    const pairs = Object.keys(resp.auth).sort().map((k) => k + "=" + resp.auth[k]);
    lines.push("policy: auth overrides: " + pairs.join(", "));
  }
  if (resp.aliases && Object.keys(resp.aliases).length) {
    const pairs = Object.keys(resp.aliases).sort().map((k) => k + " → " + resp.aliases[k]);
    lines.push("policy: aliases: " + pairs.join(", "));
  }
  return lines;
}

// tryPasskeyPresence runs a passkey ceremony to authorize a trust grant and
// returns its one-time presence token, or null if no passkey can authorize or
// the user cancels — in which case the caller falls back to the password.
async function tryPasskeyPresence(vault) {
  try {
    if (!(window.bynPasskey && await window.bynPasskey.canUnlock(vault))) return null;
    const r = await window.bynPasskey.signIn(vault);
    return r && r.presence_token ? r.presence_token : null;
  } catch (e) { return null; }
}
async function doDelete(s) {
  const c = await confirmDelete(state.scope.vault, "Delete env-var",
    `Delete “${s.name}” from ${state.scope.vault}/${state.scope.project}/${state.scope.env}?`);
  if (!c) return;
  try { await apiWithAuth("POST", "/api/entry/delete", { scope: curScope(), name: s.name, password: c.password }, state.scope.vault); toast("deleted " + s.name); await loadEntries(); }
  catch (e) { toast(e.message, true); }
}

// revertOverride drops this (non-default) env's override so the var falls back
// to the default value. It is just a delete of the current-scope row — the
// name still exists in default, so the row re-renders as inherited (↓).
//   Unlocked: instant, no modal. The value is captured first (one reveal) so
//     the "undo" toast can re-apply it as an override.
//   Locked: the value cannot be decrypted to capture, so there is no undo; a
//     password-prompted confirm authorizes the delete (the vault stays locked).
async function revertOverride(s) {
  const vault = state.scope.vault;
  if (vaultLocked(vault)) {
    const r = await openDialog({
      title: "Revert override", danger: true, okText: "revert",
      message: `Revert “${s.name}” to its default value? This env's override is removed; the default env is kept.` +
        "\n\nThis vault is locked — enter the master password to authorize it. The vault stays locked.",
      fields: [{ key: "password", label: "master password", type: "password", placeholder: "password",
        validate: (v) => (v ? null : "password required") }],
    });
    if (!r) return;
    try {
      await apiWithAuth("POST", "/api/entry/delete", { scope: curScope(), name: s.name, password: r.password }, vault);
      toast("reverted " + s.name + " to default");
      await loadEntries();
    } catch (e) { toast(e.message, true); }
    return;
  }
  // Unlocked: capture the override value first so the undo can restore it.
  let old;
  try { old = await revealValue(s); } catch (e) { toast(e.message, true); return; }
  try { await apiWithAuth("POST", "/api/entry/delete", { scope: curScope(), name: s.name }, vault); }
  catch (e) { toast(e.message, true); return; }
  await loadEntries();
  const scope = curScope(); // pin the scope for the undo closure
  toastUndo("reverted " + s.name + " to default", async () => {
    try {
      await apiWithAuth("POST", "/api/entries", { scope, name: s.name, value: old, create_only: true }, vault);
      toast("restored override " + s.name);
      await loadEntries();
    } catch (e) { toast(e.message, true); }
  });
}

// persistToDefault promotes this (non-default) env's value into the default
// env, then drops the local copy so this env — and every env inheriting
// default — resolves to it (the row re-renders as inherited ↓).
//   Requires the vault unlocked: writing to default must encrypt with the
//   in-memory key (mirrors edit/add). A confirm precedes it because, unlike
//   revert, it mutates the SHARED default and changes what sibling envs see —
//   and for an override it replaces default's existing value.
async function persistToDefault(s) {
  const vault = state.scope.vault;
  if (vaultLocked(vault)) { toast("unlock the vault to set a default", true); return; }
  const isOverride = state.defaultNames.has(s.name);
  const ok = await openDialog({
    title: isOverride ? "Set as default" : "Save to default", okText: "persist",
    message: isOverride
      ? `Set “${s.name}”'s default to this env's value? Every env inheriting default will use it — the current default value is replaced.`
      : `Save “${s.name}” to the default env? It becomes available to every env that inherits default.`,
  });
  if (!ok) return;
  let value;
  try { value = await revealValue(s); } catch (e) { toast(e.message, true); return; }
  const defScope = { vault, project: state.scope.project, env: "default" };
  try { await apiWithAuth("POST", "/api/entries", { scope: defScope, name: s.name, value }, vault); }
  catch (e) { toast("could not write default: " + e.message, true); return; }
  // Drop the local copy so this env inherits the new default. If this fails the
  // promote already succeeded — surface it rather than silently leaving a dupe.
  try { await apiWithAuth("POST", "/api/entry/delete", { scope: curScope(), name: s.name }, vault); }
  catch (e) {
    await loadEntries();
    toast(s.name + " saved to default, but its " + state.scope.env + " copy remains — remove it manually", true);
    return;
  }
  await loadEntries();
  toast(isOverride ? ("set " + s.name + " as default") : ("saved " + s.name + " to default — available to all envs"));
}

// ---- .byn studio --------------------------------------------------------
//
// A full-screen overlay view for creating, editing, and testing .byn files.
// It is accessed via the .byn button (generateByn → openBynStudio) and via
// an "edit" action on trusted .byn rows in the trust view.
//
// The studio has two modes:
//   "builder"  — form-driven; serialises to TOML client-side (pure string
//                building, no TOML lib) for live validation.
//   "raw"      — TOML textarea; seeded from builder or loaded from file.
//
// Switching builder → raw seeds the textarea from the current form state.
// Switching raw → builder is NOT supported (no JS TOML parser); raw mode
// stays raw until the user explicitly resets. The daemon validates on every
// debounced change and the Save button is disabled while errors exist.

// studioState holds the mutable studio session. Re-created on each open.
let studioState = null;

// fetchVaultVarNames fetches entry names for a given scope from /api/entries.
// Names-only (no values) — works while the vault is locked; this is the core
// byn promise. Returns [] on any error (locked/empty vault is graceful).
async function fetchVaultVarNames(vault, project, env) {
  if (!vault) return [];
  try {
    const p = enc(project || "default");
    const e = enc(env || "default");
    const data = await api("GET", `/api/entries?vault=${enc(vault)}&project=${p}&env=${e}`);
    return (data.secrets || []).map((s) => s.name);
  } catch (_) { return []; }
}

// applyParsedToState copies a BynParsed payload into studioState fields.
// vaultVarNames is the current set of known vault var names (may be empty).
// This is used for both initial load and reset.
function applyParsedToState(parsed, vaultVarNames) {
  if (!studioState || !parsed) return;
  studioState.vault   = parsed.scope ? (parsed.scope.vault   || "") : "";
  studioState.project = parsed.scope ? (parsed.scope.project || "") : "";
  studioState.env     = parsed.scope ? (parsed.scope.env     || "") : "";
  studioState.envAll  = !!parsed.env_wildcard;
  // Split file env into vault-var toggles and custom rows.
  const vaultSet = new Set(vaultVarNames);
  studioState.envVarSwitches = {}; // vault var name → included bool
  studioState.envVars = [];        // custom (non-vault) var names
  for (const name of (parsed.env || [])) {
    if (name === "*") continue; // handled by envAll
    if (vaultSet.has(name)) {
      studioState.envVarSwitches[name] = true; // in file → ON
    } else {
      studioState.envVars.push(name);
    }
  }
  // Vault vars NOT in the file get an OFF switch.
  for (const name of vaultVarNames) {
    if (!(name in studioState.envVarSwitches)) {
      studioState.envVarSwitches[name] = false;
    }
  }
  // Actions wildcard ("*") is represented by the "allow ALL commands" checkbox
  // (mirrors env "*") — not a literal "*" row. Filter any "*" out of the list.
  studioState.actionsAll = !!parsed.actions_wildcard;
  studioState.actions = (parsed.actions || []).filter((a) => a !== "*");
  studioState.writable = (parsed.writable || []).filter((w) => typeof w === "string" && w.trim());
  studioState.aliases = Object.entries(parsed.aliases || {}).map(([n, c]) => ({ name: n, cmd: c }));
  const authKeys = ["get", "update", "delete", "exec"];
  studioState.auth = { get: "default", update: "default", delete: "default", exec: "default" };
  for (const k of authKeys) {
    if (parsed.auth && parsed.auth[k]) studioState.auth[k] = parsed.auth[k];
  }
}

// Placeholder types table — copied verbatim from docs/byn-file-format.md so
// the portal and the docs agree.
const PLACEHOLDER_ROWS = [
  ["{{uuid}}",    "UUID (any case, with or without hyphens)",                          "aws sts get-caller-identity --role-session-name {{uuid}}"],
  ["{{int}}",     "Integer (optional leading minus, then digits only)",                "kubectl scale --replicas={{int}} deploy/app"],
  ["{{alnum}}",   "Alphanumeric string (letters and digits)",                          "kubectl get {{alnum}}"],
  ["{{str}}",     "Any single non-empty token (no whitespace)",                        "git commit -m {{str}}"],
  ["{{path}}",    "Any non-empty token without a NUL byte",                            "aws s3 cp {{path}} {{path}}"],
  ["{{url}}",     "An HTTP(S) URL",                                                    "curl -o {{path}} {{url}}"],
  ["{{re:...}}", "Custom RE2 regular expression anchored to the full token",           "my-cmd --env={{re:[a-z]+}}"],
  ["{{args}}",    "Zero or more remaining tokens (tail wildcard — must be last)",      "pytest {{args}}"],
];

// serializeStudio builds the TOML string from the current studio form state.
// Pure string construction — no TOML lib.
function serializeStudio(st) {
  const lines = [];

  // [scope]
  const vault   = (st.vault   || "").trim();
  const project = (st.project || "").trim();
  const env     = (st.env     || "").trim();
  if (vault || project || env) {
    lines.push("[scope]");
    if (vault)   lines.push("vault   = " + tomlStr(vault));
    if (project) lines.push("project = " + tomlStr(project));
    if (env)     lines.push("env     = " + tomlStr(env));
    lines.push("");
  }

  // [exec]
  // Collect included vault-var names (switch ON) + custom var names.
  const vaultIncluded = Object.entries(st.envVarSwitches || {})
    .filter(([, on]) => on).map(([name]) => name);
  const customVars = (st.envVars || []).filter((v) => v.trim());
  const envVars = [...vaultIncluded, ...customVars];
  const envAll     = st.envAll || false;
  const actionsAll = st.actionsAll || false;
  const actions    = (st.actions  || []).filter((a) => a.trim());
  const writable   = (st.writable || []).map((w) => w.trim()).filter(Boolean);
  const mode = st.formatMode === "pretty" ? "pretty" : "minified";
  if (envVars.length || envAll || actions.length || actionsAll || writable.length) {
    lines.push("[exec]");
    if (envAll) {
      lines.push(...fmtTomlArray("env", ["*"], mode));
    } else if (envVars.length) {
      lines.push(...fmtTomlArray("env", envVars, mode));
    }
    if (actionsAll) {
      lines.push(...fmtTomlArray("actions", ["*"], mode));
    } else if (actions.length) {
      lines.push(...fmtTomlArray("actions", actions, mode));
    }
    if (writable.length) {
      lines.push(...fmtTomlArray("writable", writable, mode));
    }
    lines.push("");
  }

  // [auth]
  const authKeys = ["get", "update", "delete", "exec"];
  const authPairs = authKeys.filter((k) => st.auth && st.auth[k] && st.auth[k] !== "default");
  if (authPairs.length) {
    lines.push("[auth]");
    for (const k of authPairs) lines.push(k + " = " + tomlStr(st.auth[k]));
    lines.push("");
  }

  // [aliases]
  // Both key and value are quoted so that alias names with spaces or special
  // characters round-trip cleanly through the daemon's TOML parser.
  const aliases = (st.aliases || []).filter((a) => a.name.trim() && a.cmd.trim());
  if (aliases.length) {
    lines.push("[aliases]");
    for (const a of aliases) lines.push(tomlStr(a.name.trim()) + " = " + tomlStr(a.cmd.trim()));
    lines.push("");
  }

  return lines.join("\n");
}

function tomlStr(s) {
  // Minimal TOML basic string: escape backslash and double-quote.
  return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
}

// fmtTomlArray renders a TOML "key = [...]" assignment honoring the studio's
// chosen format mode. Keys are left-padded to 7 columns so "env" and "actions"
// line up. "pretty" puts each element on its own line (4-space indent, trailing
// comma) — env and actions look identical; "minified" keeps the array on one
// line. Returns an array of lines.
function fmtTomlArray(key, items, mode) {
  const lbl = key.padEnd(7);
  if (mode === "pretty") {
    const out = [lbl + " = ["];
    for (const it of items) out.push("    " + tomlStr(it) + ",");
    out.push("]");
    return out;
  }
  return [lbl + " = [" + items.map(tomlStr).join(", ") + "]"];
}

// Studio .byn array format preference ("minified" | "pretty"), persisted in
// localStorage like the theme switcher. Defaults to "minified".
const STUDIO_FORMAT_KEY = "byn.studio.format";
function loadStudioFormat() {
  return localStorage.getItem(STUDIO_FORMAT_KEY) === "pretty" ? "pretty" : "minified";
}

// toggleStudioFormat flips the array format mode, persists it, updates the
// topbar label, and reflows the current view. In builder mode the form is
// unchanged — only the serialized output / dirty-state shifts. In raw mode the
// textarea is re-parsed via byn.validate and re-serialized; invalid or empty
// content is left exactly as typed (we never mangle unparseable TOML).
async function toggleStudioFormat() {
  if (!studioState) return;
  const next = studioState.formatMode === "pretty" ? "minified" : "pretty";
  studioState.formatMode = next;
  localStorage.setItem(STUDIO_FORMAT_KEY, next);
  if (studioState.formatCb) {
    studioState.formatCb.checked = next === "pretty";
  }
  if (!studioState.rawMode) {
    // Builder mode: re-validate so the save payload preview stays in sync.
    scheduleValidation();
    return;
  }
  // Raw mode: reformat by round-tripping the textarea through the parser.
  const rawContent = studioState.rawContent || "";
  if (rawContent.trim() === "") return;
  let resp;
  try {
    resp = await api("POST", "/api/byn/validate", { content: rawContent });
  } catch (e) {
    resp = { errors: [], warnings: [], parsed: null };
  }
  const errors = (resp && resp.errors) || [];
  if (errors.length > 0 || !resp.parsed) {
    // Can't safely reformat invalid/unparseable TOML — leave it as typed.
    if (studioState.rawPanel) {
      const old = studioState.rawPanel.querySelector(".studio-format-notice");
      if (old) old.remove();
      const notice = el("div", "studio-switch-notice studio-format-notice");
      notice.textContent = "fix the errors below to reformat — content left as typed";
      studioState.rawPanel.insertBefore(notice, studioState.rawPanel.firstChild);
    }
    scheduleValidation();
    return;
  }
  // Valid — carry the parsed values into state and re-serialize in the new mode.
  applyParsedToState(resp.parsed, studioState.vaultVarNames);
  const content = serializeStudio(studioState);
  studioState.rawContent = content;
  if (studioState.rawTA) studioState.rawTA.value = content;
  if (studioState.rawPanel) {
    const old = studioState.rawPanel.querySelector(".studio-format-notice");
    if (old) old.remove();
  }
  scheduleValidation();
}

// currentContent returns the TOML string for validation/simulate/save.
// In raw mode this is the textarea value; in builder mode it is serialized.
function currentContent() {
  if (!studioState) return "";
  if (studioState.rawMode) return studioState.rawContent || "";
  return serializeStudio(studioState);
}

// ---- debounced validation -----------------------------------------------

let _validateTimer = null;
function scheduleValidation() {
  clearTimeout(_validateTimer);
  _validateTimer = setTimeout(runValidation, 400);
}

async function runValidation() {
  if (!studioState) return;
  const content = currentContent();
  const panel = studioState.validPanel;
  if (!panel) return;
  panel.textContent = "validating…";
  panel.className = "studio-valid checking";
  try {
    const r = await api("POST", "/api/byn/validate", { content });
    renderValidation(r.errors || [], r.warnings || []);
  } catch (e) {
    panel.textContent = "validation unavailable: " + e.message;
    panel.className = "studio-valid warn";
    setSaveEnabled(true); // allow save if daemon unreachable
  }
}

function renderValidation(errors, warnings) {
  if (!studioState) return;
  const panel = studioState.validPanel;
  if (!panel) return;
  panel.textContent = "";
  const hasErrors = errors.length > 0;
  if (!errors.length && !warnings.length) {
    panel.appendChild(el("span", "valid-ok", "✓ no issues"));
    panel.className = "studio-valid ok";
  } else {
    for (const issue of errors) {
      const row = el("div", "valid-row valid-err");
      const chip = el("span", "valid-chip chip-err"); chip.textContent = issue.section || "error";
      row.appendChild(chip);
      row.appendChild(el("span", "valid-msg", issue.message));
      panel.appendChild(row);
    }
    for (const issue of warnings) {
      const row = el("div", "valid-row valid-warn");
      const chip = el("span", "valid-chip chip-warn"); chip.textContent = issue.section || "warn";
      row.appendChild(chip);
      row.appendChild(el("span", "valid-msg", issue.message));
      panel.appendChild(row);
    }
    panel.className = "studio-valid " + (hasErrors ? "has-errors" : "has-warnings");
  }
  setSaveEnabled(!hasErrors);
}

function setSaveEnabled(enabled) {
  if (!studioState || !studioState.saveBtn) return;
  studioState.saveBtn.disabled = !enabled;
  studioState.saveBtn.title = enabled ? "save .byn to disk" : "fix validation errors before saving";
}

// ---- command tester -------------------------------------------------

async function runSimulate() {
  if (!studioState) return;
  const cmdLine = studioState.simInput ? studioState.simInput.value.trim() : "";
  if (!cmdLine) { toast("enter a command to test", true); return; }
  const content = currentContent();
  const result = studioState.simResult;
  if (!result) return;
  result.textContent = "running…";
  result.className = "sim-result running";
  try {
    const r = await api("POST", "/api/byn/simulate", { content, command_line: cmdLine });
    renderSimResult(r, result);
  } catch (e) {
    result.textContent = "error: " + e.message;
    result.className = "sim-result error";
  }
}

function renderSimResult(r, result) {
  result.textContent = "";
  result.className = "sim-result";

  // Verdict badge
  const badge = el("span", "sim-badge " + (r.verdict === "free" ? "free" : "auth"));
  badge.textContent = r.verdict === "free" ? "FREE" : "NEEDS AUTH";
  result.appendChild(badge);

  // Matched-by line
  const matched = el("div", "sim-matched");
  if (r.matched_kind === "wildcard") {
    matched.textContent = 'matched by wildcard "*" — all commands run free';
  } else if (r.matched_kind === "action") {
    let txt = 'matched action "' + (r.matched_action || "") + '"';
    if (r.matched_alias) txt += ' (via alias "' + r.matched_alias + '")';
    matched.textContent = txt;
  } else if (r.matched_kind === "none") {
    matched.textContent = "no matching action — " + (r.reason || "requires authorization");
  } else {
    matched.textContent = r.reason || "";
  }
  result.appendChild(matched);

  // Resolved argv (monospace, textContent only — never innerHTML)
  if (r.resolved_argv && r.resolved_argv.length) {
    const argv = el("div", "sim-argv");
    argv.textContent = r.resolved_argv.join(" ");
    result.appendChild(argv);
  }
}

// ---- open existing .byn -------------------------------------------------

async function studioOpenExisting() {
  // Show trust list + dir picker choice.
  let pickedPath = null;

  // Offer trusted list first (quick path).
  let trustEntries = [];
  try {
    const td = await api("GET", "/api/trust");
    trustEntries = td.entries || [];
  } catch (_) {}

  if (trustEntries.length) {
    pickedPath = await openTrustPicker(trustEntries);
    if (pickedPath === undefined) return; // cancelled
  }

  // If no trusted files or user chose "browse", show dir picker to pick a dir.
  if (!pickedPath) {
    const dir = await pickDirectory("");
    if (!dir) return;
    pickedPath = dir.endsWith("/.byn") ? dir : dir + "/.byn";
  }

  // Load via byn.read (POST — sameOrigin-protected).
  try {
    const r = await api("POST", "/api/byn/read", { path: pickedPath });
    await studioLoadFile(r);
  } catch (e) { toast("cannot read " + pickedPath + ": " + e.message, true); }
}

// pathEllipsisEl renders an absolute path with MIDDLE truncation: the leading
// directories collapse behind an ellipsis while the last two segments (the part
// that distinguishes one .byn from another) stay fully visible. The full path is
// shown on hover via the title tooltip. Used by the trust picker, whose entries
// otherwise all share a long common prefix and truncate to look identical.
function pathEllipsisEl(full) {
  const wrap = el("span", "sp-path");
  wrap.title = full;
  const segs = String(full || "").split("/");
  const tailCount = Math.min(2, segs.length);
  const headStr = segs.slice(0, segs.length - tailCount).join("/");
  const tailStr = (headStr ? "/" : "") + segs.slice(segs.length - tailCount).join("/");
  if (headStr) wrap.appendChild(el("span", "sp-path-head", headStr));
  wrap.appendChild(el("span", "sp-path-tail", tailStr));
  return wrap;
}

// openTrustPicker shows a simple list of trusted files and lets the user
// choose one, or pick "browse filesystem…". Returns the chosen path, null for
// browse, or undefined for cancel.
function openTrustPicker(entries) {
  return new Promise((resolve) => {
    const ovl = document.createElement("div");
    ovl.className = "studio-picker-ovl";
    const card = document.createElement("div");
    card.className = "studio-picker-card";

    const title = el("div", "studio-picker-title", "open trusted .byn");
    card.appendChild(title);

    const list = el("div", "studio-picker-list");
    for (const e of entries) {
      const btn = el("button", "studio-picker-item");
      const hash = el("span", "sp-hash"); hash.textContent = (e.sha256 || "").slice(0, 8);
      btn.appendChild(hash); btn.appendChild(pathEllipsisEl(e.path));
      btn.title = e.path;
      btn.onclick = () => { document.body.removeChild(ovl); resolve(e.path); };
      list.appendChild(btn);
    }
    card.appendChild(list);

    const foot = el("div", "studio-picker-foot");
    const browse = el("button", "btn btn-ghost sm", "browse filesystem…");
    browse.onclick = () => { document.body.removeChild(ovl); resolve(null); };
    const cancel = el("button", "btn btn-ghost sm", "cancel");
    cancel.onclick = () => { document.body.removeChild(ovl); resolve(undefined); };
    foot.appendChild(browse); foot.appendChild(cancel);
    card.appendChild(foot);

    ovl.appendChild(card);
    document.body.appendChild(ovl);
  });
}

// studioLoadFile takes a byn/read API response object {path, content,
// trust_status, parsed?, parse_error?}. When parsed is present, it
// pre-populates the builder and stays in builder mode; otherwise it falls
// back to raw mode (with a parse-error notice if parse_error is set).
async function studioLoadFile(resp) {
  if (!studioState) return;
  const path = resp.path || "";
  const content = resp.content || "";
  const trustStatus = resp.trust_status || "untrusted";
  const parsed = resp.parsed || null;
  const parseError = resp.parse_error || "";

  studioState.filePath = path;

  // Update the URL to /studio?path=<encoded> so the session is copyable/bookmarkable.
  // Guard: if the URL already equals the target (deep-link entry or navigate()
  // already pushed it), skip the pushState so Back doesn't re-trigger a render
  // loop. Three entry paths:
  //   1. Deep-link boot: renderFromLocation → openBynStudio → studioLoadFile.
  //      location is already /studio?path=X — no push needed.
  //   2. openStudioForPath (trust-row edit): navigate("/studio?path=X") already
  //      called pushState before renderFromLocation → openBynStudio → here.
  //      Again: already at target — skip.
  //   3. Combobox / dir-input pick: studioLoadFromDir → studioLoadFile.
  //      URL is /studio (no path param) — push needed.
  const targetURL = "/studio?path=" + enc(path);
  if (window.location.pathname + window.location.search !== targetURL) {
    history.pushState(null, "", targetURL);
  }

  // Update trust chip.
  if (studioState.trustChip) {
    studioState.trustChip.textContent = trustStatus;
    studioState.trustChip.className = "studio-trust-chip trust-" + trustStatus;
    studioState.trustChip.hidden = false;
  }
  // Update the dir field to the containing directory. Record it as the loaded
  // dir so the dir-input blur handler won't redundantly reload it (which would
  // re-run this function and clobber a switch-to-raw — see the blur handler).
  const dir = path.replace(/\/[^/]+$/, "");
  if (studioState.dirInput) studioState.dirInput.value = dir;
  studioState.loadedDir = dir;

  if (parsed) {
    // Clean parse → pre-populate builder and stay in builder mode.
    // Snapshot the parsed state for Reset.
    studioState.originalParsed = parsed;

    // Fetch vault var names for the parsed scope before applying.
    const vaultNames = await fetchVaultVarNames(
      parsed.scope ? parsed.scope.vault   : "",
      parsed.scope ? parsed.scope.project : "",
      parsed.scope ? parsed.scope.env     : ""
    );
    studioState.vaultVarNames = vaultNames;

    applyParsedToState(parsed, vaultNames);

    // Ensure we are in builder mode.
    studioState.rawMode = false;
    studioState.rawContent = "";
    if (studioState.builderPanel) {
      studioState.builderPanel.hidden = false;
      renderBuilderPanel(studioState.builderPanel);
    }
    if (studioState.rawPanel) studioState.rawPanel.hidden = true;
    if (studioState.modeToggle) {
      studioState.modeToggle.textContent = "switch to raw";
      studioState.modeToggle.dataset.mode = "builder";
    }
    // Show parse-error notice if content itself wasn't clean (shouldn't happen
    // when parsed is non-nil, but guard anyway).
    if (parseError && studioState.builderPanel) {
      const notice = el("div", "studio-parse-notice");
      notice.textContent = "note: parse issue — builder loaded best-effort: " + parseError;
      studioState.builderPanel.insertBefore(notice, studioState.builderPanel.firstChild);
    }
  } else {
    // Parse failure → fall back to raw mode.
    studioState.rawMode = true;
    studioState.rawContent = content;
    if (studioState.rawTA) studioState.rawTA.value = content;
    if (studioState.builderPanel) studioState.builderPanel.hidden = true;
    if (studioState.rawPanel) studioState.rawPanel.hidden = false;
    if (studioState.modeToggle) {
      studioState.modeToggle.textContent = "switch to builder";
      studioState.modeToggle.dataset.mode = "raw";
    }
    // Show parse-error notice above raw textarea.
    if (parseError && studioState.rawPanel) {
      // Remove existing notice if any.
      const old = studioState.rawPanel.querySelector(".studio-parse-notice");
      if (old) old.remove();
      const notice = el("div", "studio-parse-notice");
      notice.textContent = "builder unavailable — could not parse: " + parseError;
      studioState.rawPanel.insertBefore(notice, studioState.rawPanel.firstChild);
    }
  }

  // Update dirty-tracking baseline to the just-loaded content so the user
  // has to change something before the guard fires.
  studioBaseline = currentContent();

  scheduleValidation();
  toast("loaded " + path + " [" + trustStatus + "]");
}

// ---- studio trust/save flow ---------------------------------------------

async function studioSave() {
  if (!studioState) return;
  const dir = studioState.dirInput ? studioState.dirInput.value.trim() : "";
  if (!dir) { toast("set a project directory before saving", true); return; }

  const content = currentContent();
  const filePath = dir.endsWith("/.byn") ? dir : dir + "/.byn";

  // Confirm overwrite when loading an existing file.
  if (studioState.filePath && studioState.filePath !== filePath) {
    const ok = await openDialog({
      title: "Overwrite?",
      message: "This will overwrite " + filePath + ". Proceed?",
      okText: "overwrite",
    });
    if (!ok) return;
  }

  // Ask about trust.
  const trustDialog = await openDialog({
    title: "Save .byn",
    okText: "save",
    message: "Save to " + filePath + "?",
    fields: [
      { key: "trust", label: "trust now (so byn exec can use it immediately)", type: "checkbox",
        value: studioState.filePath ? false : true },
    ],
  });
  if (!trustDialog) return;

  let trust = trustDialog.trust;
  let password = "", presence = "";
  const vault = studioState.vault || state.scope.vault || "";
  if (trust) {
    presence = (await tryPasskeyPresence(vault)) || "";
    if (!presence) {
      const pw = await openDialog({
        title: "Trust this .byn",
        message: "Enter your master password to trust " + filePath + " so byn exec can use it.",
        okText: "trust",
        fields: [{ key: "password", label: "master password", type: "password" }],
        validate: (v) => v.password ? null : "the master password is required to trust",
      });
      if (pw && pw.password) { password = pw.password; }
      else { trust = false; toast("saving without trust", false); }
    }
  }

  try {
    const resp = await api("POST", "/api/byn/write", {
      dir, content, trust, password, presence_token: presence,
    });
    studioState.filePath = resp.path;
    // Update baseline so the guard does not fire after a clean save.
    studioBaseline = content;
    let msg = ".byn saved → " + resp.path + (resp.trusted ? " · trusted" : "");
    let toastDur = 2000;
    if (resp.trusted) {
      const policyLines = buildPolicyLines(resp);
      if (policyLines.length) { msg += "\n" + policyLines.join("\n"); toastDur = 6000; }
    }
    // When saving WITHOUT trust, warn if the file was previously trusted or
    // changed (the trust record is now stale and byn exec will reject it).
    if (studioState.trustChip) {
      const prevStatus = studioState.trustChip.textContent;
      if (!resp.trusted && prevStatus && (prevStatus === "trusted" || prevStatus === "changed")) {
        msg += "\n(re-trust required — file was " + prevStatus + " before this save)";
        toastDur = 4000;
      }
      studioState.trustChip.textContent = resp.trusted ? "trusted" : (prevStatus || "untrusted");
      studioState.trustChip.className = "studio-trust-chip trust-" + (resp.trusted ? "trusted" : (prevStatus || "untrusted"));
      studioState.trustChip.hidden = false;
    }
    toast(msg, false, toastDur);
  } catch (e) { toast(e.message, true); }
}

// ---- studio render ------------------------------------------------------

// openBynStudio opens the studio overlay. opts.mode = "create" | "edit".
// opts.path may supply an initial .byn path to open.
function openBynStudio(opts) {
  opts = opts || {};
  const sc = curScope();

  // Build the initial studio state.
  // envVarSwitches: vault-var name → included bool (for switch-based rows).
  // envVars: custom (non-vault) var names (editable text rows).
  // vaultVarNames: last-fetched list from /api/entries (names only, works locked).
  // originalParsed: the BynParsed snapshot from the loaded file, for Reset.
  studioState = {
    vault:   sc.vault   || "",
    project: sc.project || "",
    env:     sc.env     || "",
    envVarSwitches: {},
    envVars: (state.entries || []).map((e) => e.name),
    vaultVarNames: [],
    envAll:  false,
    actions: [],
    actionsAll: false,
    writable: [],
    auth:    { get: "default", update: "default", delete: "default", exec: "default" },
    aliases: [],
    rawMode: false,
    rawContent: "",
    formatMode: loadStudioFormat(),
    filePath: null,
    loadedDir: null,
    originalParsed: null,
    dirInput: null,
    rawTA: null,
    builderPanel: null,
    rawPanel: null,
    validPanel: null,
    simInput: null,
    simResult: null,
    saveBtn: null,
    modeToggle: null,
    formatCb: null,
    trustChip: null,
    resetBtn: null,
    dirDropdownEl: null,
    trustEntries: [],
    // Reveal state: shows real env-var values inline (gated by unlock/auth).
    // Per-value: single-click toggles one; reveal-all toggles every one.
    revealValueEls: {}, // name → value <span> (rebuilt each render)
    revealTimers: {},   // name → per-value auto-hide timer
    revealBtn: null,
  };
  // Pre-populate envVarSwitches from already-loaded entries (the entries that
  // are currently displayed in the vault scope the studio was opened from).
  // All start ON (they are the "current scope" vars the user would most
  // naturally want to inject).
  for (const name of studioState.envVars) {
    studioState.envVarSwitches[name] = true;
  }
  // vaultVarNames starts as a copy of the pre-loaded entries.
  studioState.vaultVarNames = studioState.envVars.slice();
  // Custom rows start empty (all known vars are vault vars from scope).
  studioState.envVars = [];

  // Baseline for dirty-tracking: set to the initial serialization so that
  // opening the studio with a blank new file does NOT show a dirty-nav guard
  // until the user has actually changed something. Updated after every save
  // and after Reset-to-baseline.
  studioBaseline = serializeStudio(studioState);

  // State view: "studio" disables the normal content area.
  state.view = "studio";
  renderCrumbs();

  const box = $("#content-body");
  box.innerHTML = "";

  // ---- top bar ----
  const topBar = el("div", "studio-topbar");

  const left = el("div", "studio-topbar-left");
  const titleEl = el("span", "studio-title", ".byn studio");
  left.appendChild(titleEl);

  // Trust chip (hidden until a file is loaded/saved).
  const trustChip = el("span", "studio-trust-chip");
  trustChip.hidden = true;
  studioState.trustChip = trustChip;
  left.appendChild(trustChip);

  topBar.appendChild(left);

  const right = el("div", "studio-topbar-right");

  // Open existing button.
  const openBtn = el("button", "btn btn-ghost sm", "open .byn…");
  openBtn.onclick = studioOpenExisting;
  right.appendChild(openBtn);

  // Reset button — top-right of builder (hidden when in raw mode).
  const resetBtn = el("button", "btn btn-ghost sm studio-reset-btn", "reset");
  resetBtn.title = "reset to defaults (or to the original loaded file)";
  resetBtn.onclick = studioReset;
  studioState.resetBtn = resetBtn;
  right.appendChild(resetBtn);

  // Builder / Raw toggle.
  const modeToggle = el("button", "btn btn-ghost sm", "switch to raw");
  modeToggle.dataset.mode = "builder";
  modeToggle.onclick = toggleStudioMode;
  studioState.modeToggle = modeToggle;
  right.appendChild(modeToggle);

  // Save button.
  const saveBtn = el("button", "btn btn-primary sm", "save .byn");
  saveBtn.onclick = studioSave;
  studioState.saveBtn = saveBtn;
  right.appendChild(saveBtn);

  // Close button.
  const closeBtn = el("button", "btn btn-ghost sm", "close");
  closeBtn.onclick = closeStudio;
  right.appendChild(closeBtn);

  topBar.appendChild(right);
  box.appendChild(topBar);

  // ---- dir row (editable combobox) ----
  const dirRow = el("div", "studio-dir-row");
  const dirLabel = el("span", "field-label", "project directory");
  const dirWrap = el("div", "path-row");

  // Dir input wired through the shared makeCombobox helper.
  const dirInput = el("input", "input mono");
  dirInput.type = "text"; dirInput.placeholder = "/path/to/project";
  dirInput.autocomplete = "off"; dirInput.spellcheck = false;
  dirInput.autocapitalize = "off";
  // Password manager suppression: these attrs prevent Bitwarden, 1Password,
  // LastPass, etc. from treating this path field as a credential input.
  dirInput.name = "byn-dir-path";
  dirInput.setAttribute("data-bwignore", "true");
  dirInput.setAttribute("data-1p-ignore", "true");
  dirInput.setAttribute("data-lpignore", "true");
  studioState.dirInput = dirInput;

  // Build combobox using the shared helper; options come from the trust list.
  const dirCombo = makeCombobox(
    dirInput,
    // getOptions: deduplicated directory paths from the trust entries.
    () => {
      const entries = (studioState && studioState.trustEntries) || [];
      const seen = new Set();
      return entries.map((e) => e.path.replace(/\/[^/]+$/, "")).filter((d) => {
        if (seen.has(d)) return false;
        seen.add(d); return true;
      });
    },
    // onPick: load the .byn from the chosen directory.
    async (dirPath) => {
      if (studioState && studioState.dirInput) studioState.dirInput.value = dirPath;
      await studioLoadFromDir(dirPath);
    }
  );
  dirCombo.className = "studio-dir-combo";
  // Store dropdown reference for legacy studioShowDirDropdown callers.
  studioState.dirDropdownEl = dirCombo.querySelector(".studio-dir-dropdown");

  // On Enter: attempt to load .byn from typed path.
  dirInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); studioLoadFromDir(dirInput.value.trim()); }
  });
  // On blur, trigger a load for manually-typed paths only. Skip when the value
  // already equals the loaded dir (e.g. it was just picked from the dropdown) —
  // otherwise this redundant reload re-runs studioLoadFile and clobbers a
  // switch-to-raw the user made right after opening the file.
  dirInput.addEventListener("blur", () => {
    setTimeout(() => {
      const v = dirInput.value.trim();
      if (v && studioState && v !== studioState.loadedDir) studioLoadFromDir(v);
    }, 200);
  });

  const browseDirBtn = el("button", "btn btn-ghost sm path-browse", "browse…");
  browseDirBtn.type = "button";
  browseDirBtn.onclick = async () => {
    const p = await pickDirectory(dirInput.value);
    if (p) {
      dirInput.value = p;
      await studioLoadFromDir(p);
    }
  };
  dirWrap.appendChild(dirCombo); dirWrap.appendChild(browseDirBtn);
  dirRow.appendChild(dirLabel); dirRow.appendChild(dirWrap);
  box.appendChild(dirRow);

  // Fetch trust list for the combobox — async, non-blocking.
  // Do NOT call studioShowDirDropdown() here: the dropdown must be
  // closed by default and only opens on focus or typing.
  (async () => {
    try {
      const td = await api("GET", "/api/trust");
      if (studioState) {
        studioState.trustEntries = td.entries || [];
      }
    } catch (_) {}
  })();

  // ---- two-column layout: editor + validation ----
  const cols = el("div", "studio-cols");

  // Left: builder / raw panels.
  const editorCol = el("div", "studio-editor-col");

  // Builder panel.
  const builderPanel = el("div", "studio-builder");
  studioState.builderPanel = builderPanel;
  renderBuilderPanel(builderPanel);
  editorCol.appendChild(builderPanel);

  // Raw panel (hidden initially).
  const rawPanel = el("div", "studio-raw");
  rawPanel.hidden = true;
  studioState.rawPanel = rawPanel;
  const rawTA = el("textarea", "input mono area studio-raw-ta");
  rawTA.placeholder = "# paste or type TOML here\n[scope]\nvault = \"default\"";
  rawTA.spellcheck = false; rawTA.autocapitalize = "off";
  rawTA.rows = 20;
  rawTA.value = serializeStudio(studioState);
  studioState.rawTA = rawTA;
  rawTA.oninput = () => {
    studioState.rawContent = rawTA.value;
    scheduleValidation();
  };
  rawPanel.appendChild(rawTA);

  // Format checkbox (below the textarea, raw-mode only): pretty vs minified
  // array layout. Persisted in localStorage; reformats the textarea on toggle.
  const fmtRow = el("label", "studio-check-row studio-raw-fmt");
  const fmtCb = el("input"); fmtCb.type = "checkbox";
  fmtCb.checked = studioState.formatMode === "pretty";
  fmtCb.title = "lay out [exec] env and actions one entry per line (persists)";
  fmtCb.onchange = toggleStudioFormat;
  studioState.formatCb = fmtCb;
  fmtRow.appendChild(fmtCb);
  fmtRow.appendChild(el("span", null, "pretty"));
  rawPanel.appendChild(fmtRow);

  editorCol.appendChild(rawPanel);

  cols.appendChild(editorCol);

  // Right: validation + simulator.
  const sideCol = el("div", "studio-side-col");

  // Validation panel.
  const validSection = el("div", "studio-section");
  validSection.appendChild(el("div", "studio-section-head", "validation"));
  const validPanel = el("div", "studio-valid checking", "validating…");
  studioState.validPanel = validPanel;
  validSection.appendChild(validPanel);
  sideCol.appendChild(validSection);

  // Placeholder hint (collapsible).
  const hintSection = el("div", "studio-section");
  const hintHead = el("button", "studio-section-head collapsible", "action placeholders ▸");
  const hintBody = el("div", "studio-hint-body");
  hintBody.hidden = true;
  hintHead.onclick = () => {
    hintBody.hidden = !hintBody.hidden;
    hintHead.textContent = "action placeholders " + (hintBody.hidden ? "▸" : "▾");
  };
  const hintTbl = el("div", "studio-hint-tbl");
  for (const [ph, desc, example] of PLACEHOLDER_ROWS) {
    const row = el("div", "hint-row");
    const phEl = el("span", "hint-ph"); phEl.textContent = ph;
    const descEl = el("span", "hint-desc"); descEl.textContent = desc;
    const exEl = el("span", "hint-ex"); exEl.textContent = example;
    row.appendChild(phEl); row.appendChild(descEl); row.appendChild(exEl);
    hintTbl.appendChild(row);
  }
  hintBody.appendChild(hintTbl);
  hintSection.appendChild(hintHead); hintSection.appendChild(hintBody);
  sideCol.appendChild(hintSection);

  // Command tester.
  const simSection = el("div", "studio-section");
  simSection.appendChild(el("div", "studio-section-head", "command tester"));
  const simRow = el("div", "sim-row");
  const simInput = el("input", "input mono");
  simInput.type = "text"; simInput.placeholder = "try a command…  e.g. make test";
  simInput.autocomplete = "off"; simInput.spellcheck = false;
  studioState.simInput = simInput;
  simInput.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); runSimulate(); } };
  const simRun = el("button", "btn btn-ghost sm", "run");
  simRun.onclick = runSimulate;
  simRow.appendChild(simInput); simRow.appendChild(simRun);
  simSection.appendChild(simRow);
  const simResult = el("div", "sim-result");
  studioState.simResult = simResult;
  simSection.appendChild(simResult);
  sideCol.appendChild(simSection);

  cols.appendChild(sideCol);
  box.appendChild(cols);

  // Start validation.
  scheduleValidation();

  // If an initial path was provided, open it.  Do this BEFORE the
  // studioRefreshVaultVarNames call below so the load wins the race: the
  // load sets vaultVarNames from the parsed scope, and the refresh (which
  // runs on the portal's current scope, not the file's scope) must not
  // overwrite it.  We suppress the initial auto-refresh when a path is
  // pending and let studioLoadFile trigger the refresh after it applies the
  // parsed scope.
  if (opts.path) {
    api("POST", "/api/byn/read", { path: opts.path }).then((r) => {
      studioLoadFile(r).catch((e) => studioShowDeepLinkError(opts.path, e.message));
    }).catch((e) => studioShowDeepLinkError(opts.path, e.message));
    // Skip the initial auto-populate below — studioLoadFile will refresh.
    return;
  }

  // Fetch vault var names for the current scope (debounced, non-blocking).
  studioRefreshVaultVarNames();
}

// studioShowDeepLinkError renders a friendly error view when a /studio?path=
// deep-link cannot be loaded (file missing, unreadable, etc.). The daemon's
// error message is shown with a "Back to studio" button that returns to
// /studio create mode.
function studioShowDeepLinkError(path, daemonMsg) {
  const box = $("#content-body");
  box.innerHTML = "";
  // Replace URL with bare /studio so back navigates cleanly.
  history.replaceState(null, "", "/studio");

  const wrap = el("div", "studio-deeplink-err");
  const head = el("div", "studio-deeplink-err-head", "Cannot open .byn file");
  const pathEl = el("div", "studio-deeplink-err-path");
  pathEl.textContent = path;
  const msgEl = el("div", "studio-deeplink-err-msg");
  msgEl.textContent = daemonMsg || "file not found or could not be read";
  const backBtn = el("button", "btn btn-ghost sm", "back to studio");
  backBtn.onclick = () => {
    studioState = null;
    // Reopen studio in create mode.
    openBynStudio({ mode: "create" });
  };
  wrap.appendChild(head);
  wrap.appendChild(pathEl);
  wrap.appendChild(msgEl);
  wrap.appendChild(backBtn);
  box.appendChild(wrap);
}

// closeStudio leaves the studio overlay and returns to the previous view.
// Guarded: shows a byn modal when the studio has unsaved edits.
async function closeStudio() {
  await guardDirtyNav(() => {
    if (studioState) { // drop any per-value reveal timers
      for (const t of Object.keys(studioState.revealTimers || {})) clearTimeout(studioState.revealTimers[t]);
    }
    studioState = null;
    leaveOverlayView();
  });
}

// toggleStudioMode switches between builder and raw modes.
// Rule: switching NEVER discards or re-fetches — it carries the values
// currently entered in the browser. Reset is the ONLY way back to saved state.
//   builder → raw: seeds textarea from current form serialization.
//   raw → builder: validates the current raw textarea content via byn.validate;
//     errors → STAY in raw, show inline notice + validation panel shows errors;
//     zero errors → applyParsedToState(resp.parsed) and switch.
// The old discard-warning modal is gone (nothing is discarded on raw→builder
// when byn.validate succeeds — we carry the validated parsed values through).
async function toggleStudioMode() {
  if (!studioState) return;
  studioHideAll(); // never carry revealed plaintext across a mode switch
  if (!studioState.rawMode) {
    // builder → raw: seed textarea from current form state.
    const content = serializeStudio(studioState);
    studioState.rawMode = true;
    studioState.rawContent = content;
    if (studioState.rawTA) studioState.rawTA.value = content;
    if (studioState.builderPanel) studioState.builderPanel.hidden = true;
    if (studioState.rawPanel) studioState.rawPanel.hidden = false;
    if (studioState.modeToggle) {
      studioState.modeToggle.textContent = "switch to builder";
      studioState.modeToggle.dataset.mode = "raw";
    }
  } else {
    // raw → builder: validate the CURRENT raw textarea content first.
    // Errors → stay in raw with an inline notice (nothing discarded, nothing lost).
    // Zero errors → carry the parsed values into the builder state and switch.
    const rawContent = studioState.rawContent || "";
    let validateResp;
    try {
      validateResp = await api("POST", "/api/byn/validate", { content: rawContent });
    } catch (e) {
      // Daemon unreachable — fall back to allowing the switch (same as before).
      validateResp = { errors: [], warnings: [], parsed: null };
    }
    const errors = (validateResp && validateResp.errors) || [];
    if (errors.length > 0) {
      // Stay in raw mode; show the inline notice and let the validation panel
      // display the errors (scheduleValidation will refresh it).
      // Remove any existing inline switch notice before adding a new one.
      if (studioState.rawPanel) {
        const old = studioState.rawPanel.querySelector(".studio-switch-notice");
        if (old) old.remove();
        const notice = el("div", "studio-switch-notice studio-parse-notice");
        notice.textContent = "fix the errors below, or Reset to the saved file, then switch to builder";
        studioState.rawPanel.insertBefore(notice, studioState.rawPanel.firstChild);
      }
      scheduleValidation();
      return;
    }
    // Zero errors — clear any inline switch notice and carry parsed values through.
    if (studioState.rawPanel) {
      const old = studioState.rawPanel.querySelector(".studio-switch-notice");
      if (old) old.remove();
    }
    // Carry the current entered values into studioState via applyParsedToState.
    // resp.parsed is populated when there are zero errors; fall back to a noop
    // (the existing studioState fields remain as-is) if parsed is absent.
    if (validateResp && validateResp.parsed) {
      applyParsedToState(validateResp.parsed, studioState.vaultVarNames);
    }
    studioState.rawMode = false;
    studioState.rawContent = "";
    if (studioState.builderPanel) studioState.builderPanel.hidden = false;
    if (studioState.rawPanel) studioState.rawPanel.hidden = true;
    if (studioState.modeToggle) {
      studioState.modeToggle.textContent = "switch to raw";
      studioState.modeToggle.dataset.mode = "builder";
    }
    // Re-render the builder to pick up the newly carried values.
    if (studioState.builderPanel) renderBuilderPanel(studioState.builderPanel);
  }
  scheduleValidation();
}

// studioRefreshVaultVarNames fetches entry names for the current scope and
// updates studioState.vaultVarNames + re-renders the builder if in builder mode.
let _vaultVarTimer = null;
async function studioRefreshVaultVarNames() {
  if (!studioState) return;
  clearTimeout(_vaultVarTimer);
  _vaultVarTimer = setTimeout(async () => {
    if (!studioState) return;
    const names = await fetchVaultVarNames(
      studioState.vault, studioState.project, studioState.env
    );
    if (!studioState) return;
    const prev = studioState.vaultVarNames;
    studioState.vaultVarNames = names;
    // Add any new vault names as OFF switches (don't remove existing ones).
    for (const n of names) {
      if (!(n in studioState.envVarSwitches)) studioState.envVarSwitches[n] = false;
    }
    // If names changed and we're in builder mode, re-render env section only.
    if (JSON.stringify(prev) !== JSON.stringify(names) && !studioState.rawMode && studioState.builderPanel) {
      renderBuilderPanelPreserveFocus(studioState.builderPanel);
    }
  }, 300);
}

// renderBuilderPanelPreserveFocus wraps renderBuilderPanel with focus and
// caret-position save/restore so that typing in a scope field does not cause
// the user's input to lose focus when the debounced env-var refresh fires.
//
// Strategy: record the focused element's id (or constructed selector) and
// selection range before the re-render; after the re-render find the element
// by the same id/selector and restore focus + caret.
function renderBuilderPanelPreserveFocus(panel) {
  const active = document.activeElement;
  let focusId = null;
  let selStart = 0, selEnd = 0;
  // Only try to restore focus when the focused element is inside the panel.
  if (active && panel.contains(active)) {
    focusId = active.id || null;
    if (!focusId && active.name) focusId = "__name__" + active.name;
    try { selStart = active.selectionStart || 0; selEnd = active.selectionEnd || 0; } catch (_) {}
  }
  renderBuilderPanel(panel);
  if (!focusId) return;
  // Find and re-focus the replacement element.
  let target = null;
  if (focusId.startsWith("__name__")) {
    target = panel.querySelector("input[name=" + JSON.stringify(focusId.slice(8)) + "]");
  } else {
    target = panel.querySelector("#" + CSS.escape(focusId));
  }
  if (!target) return;
  target.focus();
  try { target.setSelectionRange(selStart, selEnd); } catch (_) {}
}

// studioLoadFromDir tries to load `dir/.byn` when dir is non-empty. If no
// .byn exists in the directory, resets the builder to defaults and clears
// the filePath + trust chip so the previous file's state does not bleed in.
async function studioLoadFromDir(dir) {
  if (!dir || !studioState) return;
  const bynPath = dir.endsWith("/.byn") ? dir : dir + "/.byn";
  try {
    const r = await api("POST", "/api/byn/read", { path: bynPath });
    await studioLoadFile(r);
  } catch (e) {
    // A genuinely-absent .byn is the normal "blank dir" case — reset silently.
    // Any OTHER read failure (notably a macOS Full Disk Access / TCC denial on a
    // .byn that DOES exist) must be surfaced with its actionable workflow message
    // — otherwise the dropdown path fails silently while "open .byn" shows it.
    const msg = (e && e.message) || "";
    if (!/no such file|not found|does not exist|cannot find/i.test(msg)) {
      toast(msg || ("cannot read " + bynPath), true);
    }
    // No readable .byn — reset to blank defaults and clear stale state.
    if (!studioState) return;
    studioState.filePath = null;
    studioState.originalParsed = null;
    if (studioState.trustChip) {
      studioState.trustChip.textContent = "";
      studioState.trustChip.className = "studio-trust-chip";
      studioState.trustChip.hidden = true;
    }
    if (studioState.dirInput) studioState.dirInput.value = dir;
    studioState.loadedDir = dir;
    // Reset form fields to defaults (same path as studioReset without dialog).
    studioState.vault   = "";
    studioState.project = "";
    studioState.env     = "";
    studioState.envAll  = false;
    studioState.envVars = [];
    for (const k of Object.keys(studioState.envVarSwitches)) {
      studioState.envVarSwitches[k] = false;
    }
    studioState.actions = [];
    studioState.actionsAll = false;
    studioState.writable = [];
    studioState.aliases = [];
    studioState.auth = { get: "default", update: "default", delete: "default", exec: "default" };
    if (!studioState.rawMode && studioState.builderPanel) {
      renderBuilderPanel(studioState.builderPanel);
    }
    // Refresh vault var names for any scope-related changes.
    studioRefreshVaultVarNames();
    scheduleValidation();
  }
}

// studioReset resets the builder form. If a file was loaded (originalParsed is
// set), resets to that original state. If new/unspecified, resets to defaults.
// Confirms via byn modal (item 7 — no browser dialogs).
async function studioReset() {
  if (!studioState) return;
  const confirmed = await openDialog({
    title: "Reset builder?",
    message: studioState.originalParsed
      ? "Reset the builder to the original state from the loaded file? Unsaved changes will be lost."
      : "Reset the builder to blank defaults? All current fields will be cleared.",
    okText: "reset",
  });
  if (!confirmed) return;

  if (studioState.originalParsed) {
    applyParsedToState(studioState.originalParsed, studioState.vaultVarNames);
  } else {
    // Reset to defaults.
    studioState.vault   = "";
    studioState.project = "";
    studioState.env     = "";
    studioState.envAll  = false;
    studioState.envVars = [];
    // Turn all switches OFF.
    for (const k of Object.keys(studioState.envVarSwitches)) {
      studioState.envVarSwitches[k] = false;
    }
    studioState.actions = [];
    studioState.actionsAll = false;
    studioState.writable = [];
    studioState.aliases = [];
    studioState.auth = { get: "default", update: "default", delete: "default", exec: "default" };
  }
  if (studioState.builderPanel) renderBuilderPanel(studioState.builderPanel);
  // In raw mode, reflow the textarea to the reset content too — currentContent()
  // reads the textarea in raw mode, so the re-seed must happen BEFORE the
  // baseline reset below, otherwise reset would leave the raw editor untouched.
  if (studioState.rawMode) {
    const content = serializeStudio(studioState);
    studioState.rawContent = content;
    if (studioState.rawTA) studioState.rawTA.value = content;
    if (studioState.rawPanel) {
      const oldNotice = studioState.rawPanel.querySelector(".studio-switch-notice");
      if (oldNotice) oldNotice.remove();
    }
  }
  // After reset the editor content equals the new baseline — clear dirty flag.
  studioBaseline = currentContent();
  scheduleValidation();
}

// ---- studio reveal-all (show real env-var values, gated by unlock/auth) ----

// studioScopeForReveal returns the {vault, project, env} of the scope being
// edited (project/env default like the var-name fetch).
function studioScopeForReveal() {
  return {
    vault:   (studioState.vault   || "").trim(),
    project: (studioState.project || "").trim() || "default",
    env:     (studioState.env     || "").trim() || "default",
  };
}

// studioShowValue paints fetched plaintext into a value span + arms its
// per-value auto-hide timer.
function studioShowValue(name, span, v) {
  span.classList.add("revealed");
  span.classList.toggle("studio-val-empty", v === ""); // namespaced — global .empty has 54px padding
  span.textContent = v === "" ? "(empty)" : v; // textContent — XSS-safe, clears children
  clearTimeout(studioState.revealTimers[name]);
  if (revealHideAfterMs > 0) {
    studioState.revealTimers[name] = setTimeout(() => studioHideOne(name), revealHideAfterMs);
  }
}

// studioRevealOne fetches + shows ONE value (single-click). Gated by the
// audited reveal path: vault unlocked + step-up via apiWithAuth.
async function studioRevealOne(name) {
  if (!studioState || !studioState.revealValueEls[name]) return;
  const scope = studioScopeForReveal();
  if (!scope.vault) { toast("set a vault in [scope] to reveal values", true); return; }
  try {
    const data = await apiWithAuth("POST", "/api/entry/reveal", { scope, name }, scope.vault);
    const span = studioState && studioState.revealValueEls[name];
    if (span) studioShowValue(name, span, data.value);
  } catch (e) { toast(e.message || ("could not reveal " + name), true); }
  studioUpdateRevealBtn();
}

// studioHideOne re-masks ONE value + clears its timer.
function studioHideOne(name) {
  if (!studioState) return;
  clearTimeout(studioState.revealTimers[name]);
  delete studioState.revealTimers[name];
  const span = studioState.revealValueEls[name];
  if (span) {
    span.classList.remove("revealed", "studio-val-empty");
    span.textContent = ""; // clears children (XSS-safe), then re-mask
    span.appendChild(maskDots());
  }
  studioUpdateRevealBtn();
}

// studioToggleOne flips one value between revealed and masked (single-click).
function studioToggleOne(name) {
  if (!studioState) return;
  const span = studioState.revealValueEls[name];
  if (!span) return;
  if (span.classList.contains("revealed")) studioHideOne(name);
  else studioRevealOne(name);
}

// studioAllRevealed is true when every scope var's value span is revealed.
function studioAllRevealed() {
  const names = (studioState && studioState.vaultVarNames) || [];
  if (!names.length) return false;
  return names.every((n) => {
    const s = studioState.revealValueEls[n];
    return s && s.classList.contains("revealed");
  });
}

// studioToggleRevealAll reveals every scope value at once (one up-front auth),
// or masks them all if every one is already revealed. Bound to the env-card
// button and the `R` shortcut.
async function studioToggleRevealAll() {
  if (!studioState) return;
  const names = studioState.vaultVarNames || [];
  if (!names.length || studioState.envAll) return; // nothing to reveal
  if (studioAllRevealed()) { studioHideAll(); return; }
  const scope = studioScopeForReveal();
  if (!scope.vault) { toast("set a vault in [scope] to reveal values", true); return; }
  if (studioState.revealBtn) { studioState.revealBtn.disabled = true; studioState.revealBtn.textContent = "revealing…"; }
  const vals = await studioRevealScopeValues(scope, names);
  if (!studioState) return; // studio closed mid-fetch
  if (studioState.revealBtn) studioState.revealBtn.disabled = false;
  if (!vals) { studioUpdateRevealBtn(); return; } // cancelled / locked / failed
  for (const name of names) {
    const span = studioState.revealValueEls[name];
    if (span && name in vals) studioShowValue(name, span, vals[name]);
  }
  studioUpdateRevealBtn();
}

// studioRevealScopeValues fetches plaintext for `names` in `scope`, authorizing
// once up front: a password is reused across reads; single-use passkey tokens
// cover one read, so the rest re-prompt (same as the .env export). Returns
// { name → value }, or null on cancel / locked vault / failure (with a toast).
// Each read is an audited `get`.
async function studioRevealScopeValues(scope, names) {
  const out = {};
  const ok = await revealManyValues(
    names.map((n) => ({ scope, name: n })), scope.vault,
    (req, v) => { out[req.name] = v; });
  return ok ? out : null;
}

// studioHideAll re-masks every value + clears every per-value timer.
function studioHideAll() {
  if (!studioState) return;
  for (const name of Object.keys(studioState.revealValueEls || {})) studioHideOne(name);
  // Clear any orphan timers for names no longer rendered.
  for (const name of Object.keys(studioState.revealTimers || {})) {
    clearTimeout(studioState.revealTimers[name]);
    delete studioState.revealTimers[name];
  }
  studioUpdateRevealBtn();
}

// studioUpdateRevealBtn syncs the env-card button label to the reveal state.
function studioUpdateRevealBtn() {
  if (!studioState || !studioState.revealBtn) return;
  studioState.revealBtn.textContent = studioAllRevealed() ? "hide all" : "reveal all";
}

// renderBuilderPanel fills the builder section cards into el.
function renderBuilderPanel(panel) {
  panel.innerHTML = "";

  // -- Scope card --
  const scopeCard = studioCard("scope");
  const scopeGrid = el("div", "studio-grid");

  // Vault field: options from the vaults list.
  scopeGrid.appendChild(studioScopeField("vault", "vault", studioState.vault || "", (v) => {
    studioState.vault = v; studioRefreshVaultVarNames(); scheduleValidation();
  }, async () => state.vaults.map((v) => v.name)));

  // Project field: options from /api/projects for the current vault.
  scopeGrid.appendChild(studioScopeField("project", "project", studioState.project || "", (v) => {
    studioState.project = v; studioRefreshVaultVarNames(); scheduleValidation();
  }, async () => {
    const vault = studioState.vault || state.scope.vault;
    if (!vault) return [];
    try {
      const d = await api("GET", "/api/projects?vault=" + enc(vault));
      return (d.projects || []).map((p) => p.name);
    } catch (_) { return []; }
  }));

  // Env field: options from /api/envs for the current vault+project.
  scopeGrid.appendChild(studioScopeField("env", "env", studioState.env || "", (v) => {
    studioState.env = v; studioRefreshVaultVarNames(); scheduleValidation();
  }, async () => {
    const vault = studioState.vault || state.scope.vault;
    const project = studioState.project || state.scope.project;
    if (!vault || !project) return [];
    try {
      const d = await api("GET", "/api/envs?vault=" + enc(vault) + "&project=" + enc(project));
      return (d.envs || []).map((e) => e.name);
    } catch (_) { return []; }
  }));
  scopeCard.appendChild(scopeGrid);
  panel.appendChild(scopeCard);

  // -- Inject card: env-var allowlist --
  const injCard = studioCard("inject — env");
  const injDesc = el("p", "studio-card-desc", "vars injected by byn exec (leave empty to inject nothing)");
  injCard.appendChild(injDesc);

  // Wildcard "*" toggle with loud warning.
  const allRow = el("label", "studio-check-row");
  const allCb = el("input"); allCb.type = "checkbox"; allCb.checked = !!studioState.envAll;
  allCb.onchange = () => {
    studioState.envAll = allCb.checked;
    envList.hidden = allCb.checked;
    allWarn.hidden = !allCb.checked;
    scheduleValidation();
  };
  allRow.appendChild(allCb);
  allRow.appendChild(el("span", null, "inject ALL vars (\"*\")"));
  const allWarn = el("div", "studio-warn");
  allWarn.textContent = "Warning: \"*\" injects every secret added later — including ones added after this file was trusted.";
  allWarn.hidden = !studioState.envAll;
  injCard.appendChild(allRow);
  injCard.appendChild(allWarn);

  // Per-var section (hidden when envAll is set).
  const envList = el("div", "studio-list");
  envList.hidden = !!studioState.envAll;

  // UNION rendering: show rows for vaultVarNames PLUS any ON entries in
  // envVarSwitches that are NOT in the current vault scope.  This ensures
  // EVERYTHING that would be serialized is also visible to the user (no
  // invisible over-grant).  Stale keys (present in switches but absent from
  // the current vault) are shown in a "stale / other scope" subgroup with a
  // chip so the user can deliberately keep or drop them.
  const vaultNames = studioState.vaultVarNames || [];
  const vaultSet   = new Set(vaultNames);
  const switches   = studioState.envVarSwitches || {};

  // Keys that appear in envVarSwitches but are not in the current vault scope.
  const staleKeys = Object.keys(switches).filter((k) => !vaultSet.has(k));

  // Reveal-all: value spans are rebuilt every render, so reset the registry and
  // re-attach the header button. Reveal only makes sense when the per-var list
  // is shown (real scope vars, not the "*" wildcard).
  studioState.revealValueEls = {};
  studioState.revealBtn = null;
  // Value spans are recreated, so any pending per-value timers point at stale
  // DOM — clear them; the freshly-rendered rows start masked.
  for (const t of Object.keys(studioState.revealTimers || {})) {
    clearTimeout(studioState.revealTimers[t]);
  }
  studioState.revealTimers = {};
  const canReveal = vaultNames.length > 0 && !studioState.envAll;
  if (canReveal) {
    const revealBtn = el("button", "btn btn-ghost sm studio-reveal-btn",
      studioAllRevealed() ? "hide all" : "reveal all");
    revealBtn.type = "button";
    revealBtn.title = "show the real values for this scope (R) — vault must be unlocked";
    revealBtn.onclick = studioToggleRevealAll;
    studioState.revealBtn = revealBtn;
    const head = injCard.querySelector(".studio-card-head");
    if (head) head.appendChild(revealBtn);
  }

  if (vaultNames.length > 0) {
    // -- Select all / none row (covers vault-scope vars only) --
    const selAllRow = el("div", "studio-selall-row");
    const selAllTrack = el("span", "sw-track");
    const selAllThumb = el("span", "sw-thumb");
    selAllTrack.appendChild(selAllThumb);
    const selAllLabel = el("span", null, "select all");

    const refreshSelectAll = () => {
      const vals = vaultNames.map((n) => !!(studioState.envVarSwitches || {})[n]);
      const onCount = vals.filter(Boolean).length;
      if (onCount === vaultNames.length) {
        selAllTrack.classList.remove("indeterminate");
        selAllTrack.classList.add("on");
      } else if (onCount === 0) {
        selAllTrack.classList.remove("indeterminate", "on");
      } else {
        selAllTrack.classList.remove("on");
        selAllTrack.classList.add("indeterminate");
      }
    };
    refreshSelectAll();

    selAllRow.onclick = () => {
      const vals = vaultNames.map((n) => !!(studioState.envVarSwitches || {})[n]);
      const allOn = vals.every(Boolean);
      // If all on → turn all off; otherwise turn all on.
      for (const n of vaultNames) {
        studioState.envVarSwitches[n] = !allOn;
      }
      // Re-render to sync individual toggle states.
      renderBuilderPanel(panel);
      scheduleValidation();
    };
    selAllRow.appendChild(selAllTrack);
    selAllRow.appendChild(selAllLabel);
    envList.appendChild(selAllRow);

    // Per vault-var toggle switch rows. Each gets a (masked) value span:
    // single-click reveals/hides just that value (200ms-debounced so it doesn't
    // fight the double-click); double-click toggles the include switch. Value
    // clicks stop propagation so they don't also hit the row's switch toggle.
    for (const name of vaultNames) {
      const swRow = studioSwitchRow(name, !!switches[name], (checked) => {
        studioState.envVarSwitches[name] = checked;
        refreshSelectAll();
        scheduleValidation();
      });
      const valSpan = el("span", "studio-var-val mono");
      valSpan.appendChild(maskDots());
      valSpan.title = "click to reveal / hide · double-click to toggle inject";
      studioState.revealValueEls[name] = valSpan;
      let vct = null;
      valSpan.onclick = (e) => {
        e.stopPropagation();
        if (vct) return; // a double-click is in progress
        vct = setTimeout(() => { vct = null; studioToggleOne(name); }, 200);
      };
      valSpan.ondblclick = (e) => {
        e.stopPropagation();
        if (vct) { clearTimeout(vct); vct = null; }
        swRow.click(); // toggle the include switch
      };
      swRow.appendChild(valSpan);
      envList.appendChild(swRow);
    }
  } else {
    // Vault names unavailable (locked/empty vault or no scope).
    const notice = el("div", "studio-vault-notice",
      "vault names unavailable — connect with the vault to see switch controls");
    envList.appendChild(notice);
  }

  // "stale / other scope" subgroup: keys in envVarSwitches not in current vault.
  // Only shown when at least one such key exists (hidden otherwise).
  if (staleKeys.length > 0) {
    const staleLabel = el("div", "studio-subgroup-label studio-subgroup-stale",
      "stale / other scope — not in current vault");
    envList.appendChild(staleLabel);
    for (const name of staleKeys) {
      const swRow = studioSwitchRow(name, !!switches[name], (checked) => {
        studioState.envVarSwitches[name] = checked;
        scheduleValidation();
      }, /* staleChip */ true);
      envList.appendChild(swRow);
    }
  }

  // "not in vault" subgroup label for custom vars.
  if (studioState.envVars && studioState.envVars.length > 0) {
    const subLabel = el("div", "studio-subgroup-label", "not in vault");
    envList.appendChild(subLabel);
  }

  // Custom var rows (non-vault, editable text + delete).
  // Uses studio-custom-list for the same 6px gap as other row lists.
  const customVarList = el("div", "studio-custom-list");
  for (const v of (studioState.envVars || [])) {
    customVarList.appendChild(studioVarRow(v, customVarList));
  }
  envList.appendChild(customVarList);

  const addEnvBtn = el("button", "btn btn-ghost sm studio-add-row", "+ add var");
  addEnvBtn.type = "button";
  addEnvBtn.onclick = () => {
    if (!studioState.envVars) studioState.envVars = [];
    studioState.envVars.push("");
    // Ensure "not in vault" subgroup label is visible.
    if (!customVarList.previousSibling || !customVarList.previousSibling.classList ||
        !customVarList.previousSibling.classList.contains("studio-subgroup-label")) {
      const subLabel = el("div", "studio-subgroup-label", "not in vault");
      envList.insertBefore(subLabel, customVarList);
    }
    customVarList.appendChild(studioVarRow("", customVarList));
    scheduleValidation();
  };
  envList.appendChild(addEnvBtn);
  injCard.appendChild(envList);
  panel.appendChild(injCard);

  // -- Actions card --
  const actCard = studioCard("actions — exec allowlist");
  const actDesc = el("p", "studio-card-desc",
    "commands that may run without per-call authorization (absent = every exec requires auth)");
  actCard.appendChild(actDesc);

  const actList = el("div", "studio-list");
  const wildcardWarn = el("div", "studio-warn");
  wildcardWarn.textContent = "Warning: \"*\" allows ALL commands to run without authorization — avoid in production.";

  const updateWildcardWarn = () => {
    wildcardWarn.hidden = !(studioState.actionsAll || studioState.actions.some((a) => a.trim() === "*"));
  };

  // Wildcard "*" toggle with loud warning (mirrors the env "inject ALL" toggle).
  const actAllRow = el("label", "studio-check-row");
  const actAllCb = el("input"); actAllCb.type = "checkbox"; actAllCb.checked = !!studioState.actionsAll;
  actAllCb.onchange = () => {
    studioState.actionsAll = actAllCb.checked;
    actList.hidden = actAllCb.checked;
    updateWildcardWarn();
    scheduleValidation();
  };
  actAllRow.appendChild(actAllCb);
  actAllRow.appendChild(el("span", null, "allow ALL commands (\"*\")"));
  actCard.appendChild(actAllRow);
  actCard.appendChild(wildcardWarn);

  // Per-action rows are hidden while the wildcard toggle is on.
  actList.hidden = !!studioState.actionsAll;
  updateWildcardWarn();

  for (let i = 0; i < studioState.actions.length; i++) {
    actList.appendChild(studioActionRow(i, actList, updateWildcardWarn));
  }
  const addActBtn = el("button", "btn btn-ghost sm studio-add-row", "+ add action");
  addActBtn.type = "button";
  addActBtn.onclick = () => {
    studioState.actions.push("");
    actList.insertBefore(studioActionRow(studioState.actions.length - 1, actList, updateWildcardWarn), addActBtn);
    updateWildcardWarn();
    scheduleValidation();
  };
  actList.appendChild(addActBtn);
  actCard.appendChild(actList);
  panel.appendChild(actCard);

  // -- Writable card (privsep tool-state dirs) --
  const wrCard = studioCard("writable — exec tool-state dirs (privsep)");
  const wrDesc = el("p", "studio-card-desc",
    "extra dirs the privsep exec child (_byn-exec, a different UID) may read/write — e.g. a package manager's global store under a 0700 home. Granted at trust time on top of curated defaults; each path must be under your home. Most stacks need none.");
  wrCard.appendChild(wrDesc);
  const wrList = el("div", "studio-list");
  if (!studioState.writable) studioState.writable = [];
  for (let i = 0; i < studioState.writable.length; i++) {
    wrList.appendChild(studioWritableRow(i, wrList));
  }
  const addWrBtn = el("button", "btn btn-ghost sm studio-add-row", "+ add dir");
  addWrBtn.type = "button";
  addWrBtn.onclick = () => {
    studioState.writable.push("");
    wrList.insertBefore(studioWritableRow(studioState.writable.length - 1, wrList), addWrBtn);
    scheduleValidation();
  };
  wrList.appendChild(addWrBtn);
  wrCard.appendChild(wrList);
  panel.appendChild(wrCard);

  // -- Aliases card --
  const aliasCard = studioCard("aliases");
  const aliasDesc = el("p", "studio-card-desc",
    "named entry points: byn exec <name> expands to its command");
  aliasCard.appendChild(aliasDesc);

  const aliasList = el("div", "studio-list");
  for (let i = 0; i < studioState.aliases.length; i++) {
    aliasList.appendChild(studioAliasRow(i, aliasList));
  }
  const addAliasBtn = el("button", "btn btn-ghost sm studio-add-row", "+ add alias");
  addAliasBtn.type = "button";
  addAliasBtn.onclick = () => {
    studioState.aliases.push({ name: "", cmd: "" });
    aliasList.insertBefore(studioAliasRow(studioState.aliases.length - 1, aliasList), addAliasBtn);
    scheduleValidation();
  };
  aliasList.appendChild(addAliasBtn);
  aliasCard.appendChild(aliasList);
  panel.appendChild(aliasCard);

  // -- Auth card --
  const authCard = studioCard("auth overrides");
  const authDesc = el("p", "studio-card-desc",
    "override the auth gate per operation (\"none\" = skip auth gate for this scope)");
  authCard.appendChild(authDesc);
  // One-column layout: label + select per row (not a 3+1 grid).
  const authCol = el("div", "studio-auth-col");

  for (const k of ["get", "update", "delete", "exec"]) {
    authCol.appendChild(studioAuthSelect(k));
  }
  authCard.appendChild(authCol);
  panel.appendChild(authCard);
}

function studioCard(title) {
  const card = el("div", "studio-card");
  card.appendChild(el("div", "studio-card-head", title));
  return card;
}

// makeCombobox wires a typeahead dropdown onto an existing input element.
// It returns { el: wrapperDiv } containing both the input and the dropdown.
//
// Parameters:
//   input      — the <input> element to enhance (must already exist)
//   getOptions — async fn that returns string[] of candidate values
//   onPick     — fn(value) called when a dropdown option is selected
//
// Behaviour (shared contract with the dir-combobox):
//   - Closed by default; opens on focus or typing.
//   - Contiguous case-insensitive substring filter with matched text highlighted
//     (via createElement/textContent — never innerHTML with user data).
//   - Esc closes the dropdown without changing the value.
//   - Picking an option calls onPick(value) and closes the dropdown.
//   - A mousedown on an option uses preventDefault so the input's blur fires
//     after the click, preventing a race where the dropdown hides before the
//     pick handler runs.
function makeCombobox(input, getOptions, onPick) {
  const wrapper = el("div", "studio-scope-combo");

  const dropdown = el("div", "studio-dir-dropdown");
  dropdown.hidden = true;

  wrapper.appendChild(input);
  wrapper.appendChild(dropdown);

  // _userFocused tracks whether the current focus was initiated by the user
  // (via click/pointer or Tab key) rather than programmatically. We only
  // open the dropdown on explicit user focus — never on construction.
  let _userFocused = false;
  let _mousedown = false;

  // Track mousedown/pointerdown on the input itself so we can distinguish
  // user-click focus from programmatic focus.
  input.addEventListener("pointerdown", () => { _userFocused = true; });
  dropdown.addEventListener("mousedown", () => { _mousedown = true; });

  async function showDropdown() {
    const rawQuery = input.value;
    const query = rawQuery.toLowerCase();
    let opts = [];
    try { opts = await getOptions(); } catch (_) {}

    // Filter and deduplicate.
    const seen = new Set();
    const filtered = opts.filter((o) => {
      if (seen.has(o)) return false;
      seen.add(o);
      return !query || o.toLowerCase().includes(query);
    });

    while (dropdown.firstChild) dropdown.removeChild(dropdown.firstChild);
    _kbHighlight = -1;
    if (!filtered.length) { dropdown.hidden = true; return; }

    for (const opt of filtered) {
      const item = el("div", "studio-dir-opt");
      item.setAttribute("tabindex", "-1");

      const textEl = document.createElement("div");
      textEl.className = "studio-dir-opt-dir";

      if (query) {
        const lower = opt.toLowerCase();
        const idx = lower.indexOf(query);
        if (idx >= 0) {
          if (idx > 0) textEl.appendChild(document.createTextNode(opt.slice(0, idx)));
          const hl = document.createElement("span");
          hl.className = "dir-match";
          hl.textContent = opt.slice(idx, idx + query.length);
          textEl.appendChild(hl);
          if (idx + query.length < opt.length) {
            textEl.appendChild(document.createTextNode(opt.slice(idx + query.length)));
          }
        } else {
          textEl.textContent = opt;
        }
      } else {
        textEl.textContent = opt;
      }

      item.appendChild(textEl);

      item.onmousedown = (e) => {
        e.preventDefault();
        dropdown.hidden = true;
        input.value = opt;
        onPick(opt);
      };
      dropdown.appendChild(item);
    }
    dropdown.hidden = false;
  }

  // Focus: only open the dropdown when the focus was user-initiated (click
  // or Tab navigation). Programmatic focus (e.g., restore after re-render)
  // must NOT pop the dropdown open.
  input.addEventListener("focus", () => {
    if (_userFocused) { showDropdown(); }
    _userFocused = false; // reset; Tab-into resets on the next pointerdown
  });
  // Input: user is typing — always show/refresh the dropdown.
  input.addEventListener("input", () => { showDropdown(); });
  // Blur: close the dropdown unless a dropdown option is being clicked.
  input.addEventListener("blur", () => {
    setTimeout(() => {
      if (!_mousedown) { dropdown.hidden = true; }
      _mousedown = false;
    }, 180);
  });
  // _kbHighlight tracks the currently keyboard-highlighted option index (-1 = none).
  let _kbHighlight = -1;

  function _setKbHighlight(idx) {
    const items = dropdown.querySelectorAll(".studio-dir-opt");
    _kbHighlight = idx < 0 ? -1 : Math.max(0, Math.min(idx, items.length - 1));
    items.forEach((it, i) => it.classList.toggle("sel", i === _kbHighlight));
    if (_kbHighlight >= 0 && items[_kbHighlight]) {
      items[_kbHighlight].scrollIntoView({ block: "nearest" });
    }
  }

  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { dropdown.hidden = true; _kbHighlight = -1; return; }
    // Tab-key focus is a user action — mark next focus as user-initiated.
    if (e.key === "Tab") { _userFocused = true; return; }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (dropdown.hidden) { showDropdown(); return; }
      const items = dropdown.querySelectorAll(".studio-dir-opt");
      if (!items.length) return;
      const next = e.key === "ArrowDown"
        ? (_kbHighlight + 1) % items.length
        : (_kbHighlight <= 0 ? items.length - 1 : _kbHighlight - 1);
      _setKbHighlight(next);
      // Focus stays on the input; highlighted item is tracked via _kbHighlight
      // and the .sel CSS class (no aria-activedescendant — items have no IDs).
    } else if (e.key === "Enter") {
      if (!dropdown.hidden && _kbHighlight >= 0) {
        e.preventDefault();
        const items = dropdown.querySelectorAll(".studio-dir-opt");
        if (items[_kbHighlight]) {
          const opt = items[_kbHighlight].querySelector(".studio-dir-opt-dir");
          const val = opt ? opt.textContent : items[_kbHighlight].textContent;
          dropdown.hidden = true;
          _kbHighlight = -1;
          input.value = val;
          onPick(val);
        }
      }
    }
  });

  // Close on click outside the wrapper (document-level mousedown).
  document.addEventListener("mousedown", (e) => {
    if (!wrapper.contains(e.target)) { dropdown.hidden = true; }
  });

  return wrapper;
}

// suppressPasswordManager sets attributes on an input to prevent password
// managers (Bitwarden, 1Password, LastPass, etc.) from treating it as a
// credential field. Call on every non-password studio/settings input.
function suppressPasswordManager(inp, nameAttr) {
  inp.autocomplete = "off";
  inp.name = nameAttr || "byn-field";
  inp.setAttribute("data-bwignore", "true");
  inp.setAttribute("data-1p-ignore", "true");
  inp.setAttribute("data-lpignore", "true");
}

// studioScopeField builds a scope field (vault/project/env) as a labelled
// combobox. getOptions is an async fn returning the list of known values.
// onChange(v) is called on every keystroke (same contract as studioField).
function studioScopeField(key, label, initVal, onChange, getOptions) {
  const wrap = el("label", "studio-field");
  wrap.appendChild(el("span", "field-label", label));
  const inp = el("input", "input mono");
  inp.type = "text"; inp.value = initVal; inp.spellcheck = false;
  suppressPasswordManager(inp, "byn-scope-" + key);
  inp.oninput = () => onChange(inp.value.trim());
  const combo = makeCombobox(inp, getOptions, (v) => {
    inp.value = v;
    onChange(v);
  });
  wrap.appendChild(combo);
  return wrap;
}

function studioField(key, label, initVal, onChange) {
  const wrap = el("label", "studio-field");
  wrap.appendChild(el("span", "field-label", label));
  const inp = el("input", "input mono");
  inp.type = "text"; inp.value = initVal; inp.spellcheck = false;
  suppressPasswordManager(inp, "byn-field-" + key);
  inp.oninput = () => onChange(inp.value.trim());
  wrap.appendChild(inp);
  return wrap;
}

function studioVarRow(initVal, listEl) {
  const row = el("div", "studio-row");
  const inp = el("input", "input mono studio-row-input");
  inp.type = "text"; inp.value = initVal; inp.placeholder = "VAR_NAME";
  inp.autocomplete = "off"; inp.spellcheck = false;
  // Track which index this row corresponds to via its DOM position.
  inp.oninput = () => {
    const rows = Array.from(listEl.querySelectorAll(".studio-row"));
    const idx = rows.indexOf(row);
    if (idx >= 0) studioState.envVars[idx] = inp.value.trim();
    scheduleValidation();
  };

  // "+ add to vault" button: puts the var name (with an empty value) into the
  // current studio scope, so it becomes a vault var and moves to the switch group.
  const addBtn = el("button", "act-ico studio-row-add-vault");
  addBtn.title = "add to vault (empty value)";
  addBtn.textContent = "+";
  addBtn.onclick = async () => {
    const name = inp.value.trim();
    if (!name) { toast("enter a var name first", true); return; }
    const vault   = (studioState && studioState.vault)   || state.scope.vault   || "";
    const project = (studioState && studioState.project) || state.scope.project || "default";
    const env     = (studioState && studioState.env)     || state.scope.env     || "default";
    if (!vault) { toast("set a vault in the scope first", true); return; }
    const confirmed = await openDialog({
      title: "Add to vault",
      okText: "add",
      message: `Add "${name}" (empty value) to ${vault}/${project}/${env}?\n\nThe var will appear in the vault-switch group switched ON.`,
    });
    if (!confirmed) return;
    try {
      await api("POST", "/api/entries", {
        scope: { vault, project, env },
        name,
        value: "",
        create_only: true,
      });
      toast(`added ${name} to vault`);
      // Remove from the custom list immediately so serialization does not
      // produce a duplicate while the vault-var refresh is in flight.
      if (studioState) {
        const rows = Array.from(listEl.querySelectorAll(".studio-row"));
        const idx = rows.indexOf(row);
        if (idx >= 0) studioState.envVars.splice(idx, 1);
      }
      // Refresh vault var names so the row moves to the switch group.
      await studioRefreshVaultVarNames();
      // Ensure the new var is switched ON in studioState.
      if (studioState) studioState.envVarSwitches[name] = true;
      scheduleValidation();
    } catch (e) {
      // Show inline error in the row rather than just a toast, so the user
      // sees it without losing context.
      let errEl = row.querySelector(".studio-row-inline-err");
      if (!errEl) { errEl = el("span", "studio-row-inline-err"); row.appendChild(errEl); }
      errEl.textContent = e.message;
    }
  };

  const del = el("button", "act-ico danger studio-row-del");
  del.title = "remove";
  del.appendChild(icon("trash"));
  del.onclick = () => {
    const rows = Array.from(listEl.querySelectorAll(".studio-row"));
    const idx = rows.indexOf(row);
    if (idx >= 0) studioState.envVars.splice(idx, 1);
    listEl.removeChild(row);
    scheduleValidation();
  };
  row.appendChild(inp); row.appendChild(addBtn); row.appendChild(del);
  return row;
}

// studioSwitchRow renders a toggle-switch row for a vault var name.
// name is the vault var name (textContent only — XSS safe).
// checked is the initial state. onChange(bool) is called on toggle.
// When showStaleChip is true a small "stale" chip is appended to alert the
// user that this key is not present in the current vault scope.
function studioSwitchRow(name, checked, onChange, showStaleChip) {
  const row = el("div", "studio-var-sw-row");
  const track = el("span", "sw-track");
  if (checked) track.classList.add("on");
  const thumb = el("span", "sw-thumb");
  track.appendChild(thumb);
  const label = el("span", "studio-var-sw-name");
  label.textContent = name; // textContent — XSS safe
  row.onclick = () => {
    const nowOn = track.classList.contains("on");
    if (nowOn) { track.classList.remove("on"); } else { track.classList.add("on"); }
    onChange(!nowOn);
  };
  row.appendChild(track);
  row.appendChild(label);
  if (showStaleChip) {
    const chip = el("span", "studio-stale-chip", "stale");
    chip.title = "this var is not in the current vault scope — it will still be serialized if ON";
    row.appendChild(chip);
  }
  return row;
}

function studioActionRow(idx, listEl, updateWarn) {
  const row = el("div", "studio-row studio-action-row");
  const inp = el("input", "input mono studio-row-input");
  inp.type = "text"; inp.value = studioState.actions[idx] || "";
  inp.placeholder = "make test  or  pytest {{args}}";
  inp.autocomplete = "off"; inp.spellcheck = false;
  inp.oninput = () => {
    const rows = Array.from(listEl.querySelectorAll(".studio-action-row"));
    const i = rows.indexOf(row);
    if (i >= 0) studioState.actions[i] = inp.value;
    if (updateWarn) updateWarn();
    scheduleValidation();
  };
  // Live status: indicate wildcard risk per-row.
  const statusDot = el("span", "action-status");
  statusDot.title = "";
  const updateDot = () => {
    const v = inp.value.trim();
    if (v === "*") { statusDot.className = "action-status warn"; statusDot.title = "wildcard: all commands free"; }
    else if (v.indexOf("{{args}}") !== -1) { statusDot.className = "action-status caution"; statusDot.title = "{{args}} permits arbitrary extra arguments"; }
    else if (v) { statusDot.className = "action-status ok"; statusDot.title = "pinned action"; }
    else { statusDot.className = "action-status"; statusDot.title = ""; }
  };
  updateDot();
  inp.addEventListener("input", updateDot);
  const del = el("button", "act-ico danger studio-row-del");
  del.title = "remove";
  del.appendChild(icon("trash"));
  del.onclick = () => {
    const rows = Array.from(listEl.querySelectorAll(".studio-action-row"));
    const i = rows.indexOf(row);
    if (i >= 0) studioState.actions.splice(i, 1);
    listEl.removeChild(row);
    if (updateWarn) updateWarn();
    scheduleValidation();
  };
  row.appendChild(statusDot); row.appendChild(inp); row.appendChild(del);
  return row;
}

// studioWritableRow renders one [exec] writable directory row (a path the
// privsep exec child may read/write, on top of the curated defaults).
function studioWritableRow(idx, listEl) {
  const row = el("div", "studio-row studio-writable-row");
  const inp = el("input", "input mono studio-row-input");
  inp.type = "text"; inp.value = studioState.writable[idx] || "";
  inp.placeholder = "~/Library/pnpm  or  ~/.cache/my-tool";
  inp.autocomplete = "off"; inp.spellcheck = false;
  inp.oninput = () => {
    const rows = Array.from(listEl.querySelectorAll(".studio-writable-row"));
    const i = rows.indexOf(row);
    if (i >= 0) studioState.writable[i] = inp.value;
    scheduleValidation();
  };
  const del = el("button", "act-ico danger studio-row-del");
  del.title = "remove";
  del.appendChild(icon("trash"));
  del.onclick = () => {
    const rows = Array.from(listEl.querySelectorAll(".studio-writable-row"));
    const i = rows.indexOf(row);
    if (i >= 0) studioState.writable.splice(i, 1);
    listEl.removeChild(row);
    scheduleValidation();
  };
  row.appendChild(inp); row.appendChild(del);
  return row;
}

function studioAliasRow(idx, listEl) {
  const row = el("div", "studio-row");
  const nameIn = el("input", "input mono studio-alias-name");
  nameIn.type = "text"; nameIn.value = studioState.aliases[idx] ? studioState.aliases[idx].name : "";
  nameIn.placeholder = "deploy"; nameIn.autocomplete = "off"; nameIn.spellcheck = false;
  nameIn.oninput = () => {
    const rows = Array.from(listEl.querySelectorAll(".studio-row"));
    const i = rows.indexOf(row);
    if (i >= 0) studioState.aliases[i].name = nameIn.value.trim();
    scheduleValidation();
  };
  const arrow = el("span", "alias-arrow", "→");
  const cmdIn = el("input", "input mono studio-alias-cmd");
  cmdIn.type = "text"; cmdIn.value = studioState.aliases[idx] ? studioState.aliases[idx].cmd : "";
  cmdIn.placeholder = "kubectl apply -f deploy/"; cmdIn.autocomplete = "off"; cmdIn.spellcheck = false;
  cmdIn.oninput = () => {
    const rows = Array.from(listEl.querySelectorAll(".studio-row"));
    const i = rows.indexOf(row);
    if (i >= 0) studioState.aliases[i].cmd = cmdIn.value.trim();
    scheduleValidation();
  };
  const del = el("button", "act-ico danger studio-row-del");
  del.title = "remove";
  del.appendChild(icon("trash"));
  del.onclick = () => {
    const rows = Array.from(listEl.querySelectorAll(".studio-row"));
    const i = rows.indexOf(row);
    if (i >= 0) studioState.aliases.splice(i, 1);
    listEl.removeChild(row);
    scheduleValidation();
  };
  row.appendChild(nameIn); row.appendChild(arrow); row.appendChild(cmdIn); row.appendChild(del);
  return row;
}

// makeBynSelect builds a fully custom styled dropdown to replace native <select>.
// Parameters:
//   options  — array of string option values (textContent only)
//   current  — initial selected value
//   onChange — fn(newValue) called whenever the selection changes
//   extraBtnCls — optional extra class added to the button (e.g. for warn styling)
// Returns the wrapper element (.byn-select).
//
// Keyboard: ArrowDown/ArrowUp move highlight, Enter selects, Esc closes.
// ARIA: role=listbox on panel, role=option on each option, aria-selected.
function makeBynSelect(options, current, onChange, extraBtnCls) {
  const wrapper = el("div", "byn-select");
  let selected = current;
  let open = false;

  const btn = el("button", "byn-select-btn" + (extraBtnCls ? " " + extraBtnCls : ""));
  btn.type = "button";
  btn.setAttribute("aria-haspopup", "listbox");
  btn.setAttribute("aria-expanded", "false");
  const btnText = el("span", "byn-select-val");
  btnText.textContent = selected;
  const chevron = el("span", "byn-select-chevron", "▾");
  btn.appendChild(btnText); btn.appendChild(chevron);
  wrapper.appendChild(btn);

  const panel = el("div", "byn-select-panel");
  panel.setAttribute("role", "listbox");
  panel.hidden = true;
  wrapper.appendChild(panel);

  // Build option buttons.
  const optEls = options.map((opt) => {
    const ob = el("button", "byn-select-opt");
    ob.type = "button";
    ob.setAttribute("role", "option");
    ob.setAttribute("aria-selected", String(opt === selected));
    ob.textContent = opt;
    ob.onmousedown = (e) => {
      e.preventDefault();
      pick(opt);
    };
    panel.appendChild(ob);
    return ob;
  });

  let highlightIdx = options.indexOf(selected);

  function updateHighlight(idx) {
    highlightIdx = idx;
    optEls.forEach((oe, i) => oe.classList.toggle("sel", i === idx));
    if (optEls[idx]) optEls[idx].scrollIntoView({ block: "nearest" });
  }

  function pick(val) {
    selected = val;
    btnText.textContent = val;
    const isWarn = (val === "none");
    btn.className = "byn-select-btn" + (isWarn ? " auth-none-warn" : "") + (extraBtnCls && !isWarn ? " " + extraBtnCls : "");
    optEls.forEach((oe) => oe.setAttribute("aria-selected", String(oe.textContent === val)));
    close();
    onChange(val);
  }

  function openPanel() {
    if (open) return;
    open = true;
    panel.hidden = false;
    wrapper.classList.add("open");
    btn.setAttribute("aria-expanded", "true");
    highlightIdx = options.indexOf(selected);
    updateHighlight(highlightIdx < 0 ? 0 : highlightIdx);
  }

  function close() {
    if (!open) return;
    open = false;
    panel.hidden = true;
    wrapper.classList.remove("open");
    btn.setAttribute("aria-expanded", "false");
    btn.focus();
  }

  btn.addEventListener("click", () => { if (open) close(); else openPanel(); });
  btn.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown" || e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      if (!open) { openPanel(); return; }
      if (e.key === "ArrowDown") updateHighlight((highlightIdx + 1) % options.length);
      else if (e.key === "Enter" || e.key === " ") { if (options[highlightIdx] !== undefined) pick(options[highlightIdx]); }
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (!open) { openPanel(); return; }
      updateHighlight((highlightIdx - 1 + options.length) % options.length);
    } else if (e.key === "Escape") {
      e.preventDefault(); close();
    }
  });

  // Close when clicking outside. The handler self-removes once the wrapper is
  // no longer in the document (i.e. the builder panel was re-rendered), so
  // each makeBynSelect call does not leak a permanent document listener.
  function _docMousedown(e) {
    if (!document.contains(wrapper)) { document.removeEventListener("mousedown", _docMousedown); return; }
    if (open && !wrapper.contains(e.target)) close();
  }
  document.addEventListener("mousedown", _docMousedown);

  return wrapper;
}

function studioAuthSelect(key) {
  // One-column row: label on the left, custom dropdown filling the rest.
  const row = el("div", "studio-auth-row");
  row.appendChild(el("span", "field-label", key));
  const current = studioState.auth[key] || "default";
  const isNone = current === "none";
  const sel = makeBynSelect(
    ["default", "always", "none"],
    current,
    (val) => {
      studioState.auth[key] = val;
      scheduleValidation();
    },
    isNone ? "auth-none-warn" : ""
  );
  sel.style.flex = "1";
  row.appendChild(sel);
  return row;
}

// Wire up the "edit" button in the trust view to open the studio.
// Updates the URL to /studio?path=<encoded> so the link is copyable.
function openStudioForPath(path) {
  navigateGuarded("/studio?path=" + enc(path));
}

let toastTimer = null;
// toast(msg, isErr, dur) — non-error ("ok") toasts auto-dismiss after `dur`
// (default 2000ms). ERROR toasts are PERSISTENT and Z-stacked: they never
// auto-dismiss (dur is ignored), the newest sits in front, and closing the
// front card brings the next forward — so an error is never lost behind a
// timeout or another error. See pushErrorToast.
function toast(msg, isErr, dur) {
  if (isErr) { pushErrorToast(msg); return; }
  const t = $("#toast"); t.textContent = msg; t.className = "toast ok";
  t.hidden = false; clearTimeout(toastTimer);
  const ms = dur != null ? dur : 2000;
  toastTimer = setTimeout(() => { t.hidden = true; }, ms);
}

// pushErrorToast adds a persistent error card to #toast-stack. Each card has its
// own ✕; the stack shows the newest in front with older ones peeking behind.
function pushErrorToast(msg) {
  const stack = $("#toast-stack");
  if (!stack) { console.error(msg); return; }
  const card = el("div", "toast err toast-err-card");
  card.setAttribute("role", "alert");
  const text = el("span", "toast-err-msg"); text.textContent = msg;
  const close = el("button", "toast-close", "✕");
  close.title = "dismiss";
  close.setAttribute("aria-label", "dismiss error");
  close.onclick = () => { if (card.parentNode) stack.removeChild(card); restackErrorToasts(); };
  card.appendChild(text); card.appendChild(close);
  stack.appendChild(card); // newest is the last child
  restackErrorToasts();
}

// restackErrorToasts lays the cards out in Z: the last child (newest) is depth 0
// (front, fully visible, interactive); older cards peek above with a capped
// offset and are non-interactive until they reach the front.
function restackErrorToasts() {
  const stack = $("#toast-stack");
  if (!stack) return;
  const cards = Array.from(stack.children);
  const n = cards.length;
  cards.forEach((card, i) => {
    const depth = (n - 1) - i;      // 0 for the newest (last)
    const d = Math.min(depth, 3);   // cap the visible peek so a tall stack stays put
    card.style.zIndex = String(1000 - depth);
    card.style.transform = "translateX(-50%) translateY(" + (-d * 8) + "px) scale(" + (1 - d * 0.035) + ")";
    card.style.opacity = depth === 0 ? "1" : (depth <= 3 ? "0.92" : "0");
    card.style.pointerEvents = depth === 0 ? "auto" : "none";
  });
}
// toastUndo shows an "ok" toast with a clickable "undo" affordance; clicking it
// dismisses the toast and runs undoFn. Uses a longer default window (6s) so
// there is time to react. Built from child nodes (not textContent) so the
// button survives — the ✓ prefix still comes from .toast.ok::before.
function toastUndo(msg, undoFn, dur) {
  const t = $("#toast"); t.className = "toast ok"; t.textContent = "";
  t.appendChild(document.createTextNode(msg + "  "));
  const u = el("button", "toast-undo", "undo");
  u.onclick = () => { t.hidden = true; clearTimeout(toastTimer); undoFn(); };
  t.appendChild(u);
  t.hidden = false; clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, dur != null ? dur : 6000);
}
function isTyping() { const a = document.activeElement; return !!a && (a.tagName === "INPUT" || a.tagName === "TEXTAREA" || a.isContentEditable); }
function toggleHelp() { const p = $("#help-pop"); p.hidden = !p.hidden; }
function hideHelp() { $("#help-pop").hidden = true; }
function setHelpVersion(v) {
  const el = $("#help-ver");
  if (!el || !v) return;
  const label = /^[0-9]/.test(v) ? "byn v" + v : "byn " + v; // 0.0.1 -> "byn v0.0.1"
  if (el.textContent !== label) el.textContent = label;
}

// ---- spotlight palette (Ctrl/⌘+P) ---------------------------------------

let paletteIndex = [];   // every vault/project/env as a flat searchable list
let paletteItems = [];   // current filtered + scored results
let paletteSel = 0;      // selected result index
let paletteBuilding = false;

// buildScopeIndex fetches every vault → project → env and flattens them into
// searchable items. Runs the per-vault / per-project fetches in parallel.
async function buildScopeIndex() {
  const items = [];
  let st;
  try { st = await api("GET", "/api/status"); } catch { return items; }
  const vaults = (st.vaults || []).filter((v) => v.initialized);
  await Promise.all(vaults.map(async (v) => {
    items.push({ kind: "vault", vault: v.name, label: v.name });
    let projs;
    try { projs = await api("GET", "/api/projects?vault=" + enc(v.name)); } catch { return; }
    await Promise.all((projs.projects || []).map(async (p) => {
      items.push({ kind: "project", vault: v.name, project: p.name, label: v.name + " / " + p.name });
      let envs;
      try { envs = await api("GET", "/api/envs?vault=" + enc(v.name) + "&project=" + enc(p.name)); } catch { return; }
      for (const e of (envs.envs || [])) {
        items.push({ kind: "env", vault: v.name, project: p.name, env: e.name, label: v.name + " / " + p.name + " / " + e.name });
      }
    }));
  }));
  items.sort((a, b) => a.label.localeCompare(b.label));
  return items;
}

// fuzzyScore returns a match score for query against text (higher = better),
// or -1 when not every query char appears in order. Rewards contiguous runs
// and matches at word boundaries (start, after a separator).
function fuzzyScore(query, text) {
  if (!query) return 0;
  const q = query.toLowerCase(), t = text.toLowerCase();
  let qi = 0, score = 0, last = -2, streak = 0;
  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (t[ti] === q[qi]) {
      let bonus = 1;
      if (ti === last + 1) { streak++; bonus += streak * 2; } else { streak = 0; }
      if (ti === 0 || /[\s/._-]/.test(t[ti - 1])) bonus += 3;
      score += bonus; last = ti; qi++;
    }
  }
  if (qi < q.length) return -1;
  return score - t.length * 0.05; // tie-break toward shorter labels
}

async function openPalette() {
  const pal = $("#palette");
  if (!pal.hidden) { closePalette(); return; }
  pal.hidden = false;
  const input = $("#palette-input");
  input.value = ""; input.focus();
  paletteSel = 0; paletteBuilding = true;
  renderPaletteResults();
  try { paletteIndex = await buildScopeIndex(); } finally { paletteBuilding = false; }
  if (!$("#palette").hidden) renderPaletteResults();
}
function closePalette() { $("#palette").hidden = true; }
function paletteOpen() { return !$("#palette").hidden; }

function renderPaletteResults() {
  const q = $("#palette-input").value.trim();
  const scored = [];
  for (const item of paletteIndex) {
    const s = fuzzyScore(q, item.label);
    if (s >= 0) scored.push({ item, s });
  }
  scored.sort((a, b) => b.s - a.s);
  paletteItems = scored.slice(0, 40).map((x) => x.item);
  paletteSel = 0;
  const box = $("#palette-results"); box.innerHTML = "";
  if (!paletteItems.length) {
    box.appendChild(el("div", "palette-empty", paletteBuilding ? "indexing…" : "no matches"));
    return;
  }
  paletteItems.forEach((item, i) => {
    const row = el("div", "palette-item" + (i === paletteSel ? " sel" : ""));
    row.appendChild(el("span", "pi-kind " + item.kind, item.kind));
    row.appendChild(el("span", "pi-label", item.label));
    if (vaultLocked(item.vault)) row.appendChild(el("span", "pi-lock", "🔒"));
    row.onclick = () => paletteActivate(item);
    row.onmouseenter = () => { paletteSel = i; updatePaletteSel(); };
    box.appendChild(row);
  });
}
function updatePaletteSel() {
  const rows = $("#palette-results").children;
  for (let i = 0; i < rows.length; i++) rows[i].classList.toggle("sel", i === paletteSel);
  if (rows[paletteSel]) rows[paletteSel].scrollIntoView({ block: "nearest" });
}
function paletteMove(delta) {
  if (!paletteItems.length) return;
  paletteSel = (paletteSel + delta + paletteItems.length) % paletteItems.length;
  updatePaletteSel();
}
function paletteActivate(item) {
  closePalette();
  if (item.kind === "vault") { state.open.vaults.add(item.vault); navVault(item.vault); }
  else if (item.kind === "project") { state.open.vaults.add(item.vault); state.open.projects.add(item.vault + "/" + item.project); navProject(item.vault, item.project); }
  else { state.open.vaults.add(item.vault); state.open.projects.add(item.vault + "/" + item.project); selectScope(item.vault, item.project, item.env); }
}

// ---- boot ---------------------------------------------------------------

function wire() {
  // Theme switcher: inject SVG icons then wire click handlers.
  _injectThemeIcons();
  const themeDark   = document.getElementById("theme-dark");
  const themeLight  = document.getElementById("theme-light");
  const themeSystem = document.getElementById("theme-system");
  if (themeDark)   themeDark.addEventListener("click",   () => setTheme("dark"));
  if (themeLight)  themeLight.addEventListener("click",  () => setTheme("light"));
  if (themeSystem) themeSystem.addEventListener("click", () => setTheme("system"));

  $("#new-vault-btn").addEventListener("click", createVault);
  $("#add-btn").addEventListener("click", addNewRow);
  // Double-click anywhere in the empty area of the entries view opens a new
  // var row. Ignore double-clicks that land on an existing row, the header,
  // the locked banner, or an input/button — those own their own behavior.
  $("#content-body").addEventListener("dblclick", (e) => {
    if (state.view !== "entries") return;
    if (e.target.closest(".trow, .tbl-head, .locked-banner, input, textarea, button")) return;
    addNewRow();
  });
  // Drag a .env file onto the entries view to import it.
  const cb = $("#content-body");
  const canDrop = () => state.view === "entries" && state.scope.env && !vaultLocked(state.scope.vault);
  cb.addEventListener("dragover", (e) => { if (canDrop()) { e.preventDefault(); cb.classList.add("drop"); } });
  cb.addEventListener("dragleave", (e) => { if (e.target === cb) cb.classList.remove("drop"); });
  cb.addEventListener("drop", async (e) => {
    cb.classList.remove("drop");
    if (!canDrop()) return;
    const file = e.dataTransfer && e.dataTransfer.files[0];
    if (!file) return;
    e.preventDefault();
    const pairs = parseDotenv(await file.text());
    if (!pairs.length) { toast("no KEY=value lines in dropped file", true); return; }
    const ok = await openDialog({ title: "Import dropped file", okText: "import",
      message: `Import ${pairs.length} vars from "${file.name}" into ${state.scope.env}? Existing keys are overwritten.` });
    if (!ok) return;
    await applyImport(pairs);
  });
  $("#audit-btn").addEventListener("click", toggleAudit);
  $("#trust-btn").addEventListener("click", toggleTrust);
  $("#byn-btn").addEventListener("click", generateByn);
  $("#settings-btn").addEventListener("click", toggleSettings);
  $("#help-btn").addEventListener("click", (e) => { e.stopPropagation(); toggleHelp(); });
  $("#filter").addEventListener("input", (e) => { state.filter = e.target.value; if (state.view === "entries") renderEntries(); });
  document.addEventListener("click", (e) => { if (!e.target.closest("#help-wrap")) hideHelp(); });

  // Spotlight palette: Ctrl/⌘+P opens it from anywhere (even while typing),
  // overriding the browser's print shortcut.
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === "p" || e.key === "P")) { e.preventDefault(); openPalette(); }
  }, true);
  $("#palette-input").addEventListener("input", renderPaletteResults);
  $("#palette-input").addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); paletteMove(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); paletteMove(-1); }
    else if (e.key === "Enter") { e.preventDefault(); if (paletteItems[paletteSel]) paletteActivate(paletteItems[paletteSel]); }
    else if (e.key === "Escape") { e.preventDefault(); closePalette(); }
  });
  // Click the backdrop (outside the box) to dismiss.
  $("#palette").addEventListener("mousedown", (e) => { if (e.target.id === "palette") closePalette(); });

  document.addEventListener("keydown", (e) => {
    if (paletteOpen()) return; // palette owns the keyboard while open
    if (isTyping() || dialogOpen()) return;
    if (e.key === "n" && state.view === "entries") { e.preventDefault(); addNewRow(); }
    // Lock/unlock ALWAYS hit the daemon (the source of truth) — never gated
    // on the browser's possibly-stale belief. `l` is an emergency lock: it
    // fires immediately even if the UI thinks the vault is already locked
    // (the daemon's lock is idempotent), and arms an `a` chord — `l a` then
    // locks EVERY vault.
    else if (e.key === "u") { const v = state.scope.vault; if (v) unlockVault(v); }
    else if (e.key === "l") {
      const v = state.scope.vault; if (v) lockVault(v);
      lockChordArmed = true; setTimeout(() => { lockChordArmed = false; }, 700);
    }
    else if (e.key === "a" && lockChordArmed) { lockChordArmed = false; lockAllVaults(); }
    // R reveals/hides all values (matches the TUI's R reveal) — in the studio
    // env card and in the entries view.
    else if (e.key === "R" && state.view === "studio") { e.preventDefault(); studioToggleRevealAll(); }
    else if (e.key === "R" && state.view === "entries") { e.preventDefault(); entriesToggleRevealAll(); }
    else if (e.key === "?") { e.preventDefault(); toggleHelp(); }
    else if (e.key === "Escape") hideHelp();
  });
}

async function boot() {
  // Apply the stored theme preference and wire system media-query listener.
  initTheme();
  // Exchange the one-time bootstrap token from ?auth= for the persistent
  // portal token. Must complete before any authenticated API call.
  await bootExtractToken();
  wire();
  // Listen for back/forward navigation (popstate) and re-render from the URL.
  // Guard: if the studio or settings editor has unsaved changes, show a byn
  // modal. On Stay, re-push the editor's own URL so the back press is
  // undone and the user stays in the editor.
  window.addEventListener("popstate", () => {
    // Capture the editor URL BEFORE asking the guard — if the user chooses
    // Stay we push this URL back so the history entry is restored.
    let editorURL = null;
    if (studioBaseline !== null) {
      editorURL = studioState && studioState.filePath
        ? "/studio?path=" + enc(studioState.filePath)
        : "/studio";
    } else if (cfgBaseline !== null) {
      editorURL = "/settings";
    }
    guardDirtyNav(
      () => renderFromLocation(),
      editorURL, // re-push on Stay (null = no re-push needed when not dirty)
    );
  });
  $("#app").hidden = false;
  startStatusSync();
  // Seed the cached reveal auto-hide timeout from config (non-blocking).
  loadRevealHideConfig();
  // Use the current URL to determine what to render on initial load.
  // renderFromLocation calls renderTree internally for each view.
  await renderFromLocation();
}

boot();
