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
};

// Armed for ~700ms after pressing `l`, so the `l a` chord can lock all vaults.
let lockChordArmed = false;

// ---- API ----------------------------------------------------------------

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch (_) {}
  if (!res.ok) {
    const err = new Error((data && data.error) || `${res.status} ${res.statusText}`);
    err.status = res.status;            // 423 ⇒ vault locked
    err.code = data && data.code;       // daemon error code, e.g. "locked"
    throw err;
  }
  return data;
}

// ---- per_action_auth step-up --------------------------------------------

// authorizeStepUp shows an authorization step-up for an action gated by
// [security] per_action_auth. Passkey-first (mirrors the trust-grant flow);
// falls back to the password dialog. Returns { password, presence_token } with
// exactly one of them set, or null when the user cancels.
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
      "[security] per_action_auth is on — enter the master password to authorize this action.",
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

// pickDirectory opens the daemon-backed directory browser and resolves to the
// chosen absolute path, or null if cancelled. Browsers can't return a real OS
// path from a native file dialog, so byn lists directories via the daemon
// (which runs as the user and sees only what the user can already read).
function pickDirectory(start) {
  return new Promise((resolve) => {
    const dlg = $("#dirpicker"), pathEl = $("#dirpicker-path"), listEl = $("#dirpicker-list");
    const err = $("#dirpicker-error"), use = $("#dirpicker-use"), cancel = $("#dirpicker-cancel");
    let cur = start || "";
    let done = false;

    async function load(path) {
      err.textContent = "";
      try {
        const d = await api("GET", "/api/fs/listdir" + (path ? "?path=" + enc(path) : ""));
        cur = d.path; pathEl.textContent = d.path;
        listEl.innerHTML = "";
        if (d.parent) {
          const up = el("button", "dirpicker-item up");
          up.appendChild(el("span", "di-ico", "↑")); up.appendChild(el("span", null, ".."));
          up.onclick = () => load(d.parent);
          listEl.appendChild(up);
        }
        if (!d.entries.length) listEl.appendChild(el("div", "muted dirpicker-empty", "no subfolders"));
        d.entries.forEach((e) => {
          const it = el("button", "dirpicker-item");
          it.appendChild(el("span", "di-ico", "📁")); it.appendChild(el("span", null, e.name));
          it.onclick = () => load(joinPath(cur, e.name));
          listEl.appendChild(it);
        });
      } catch (e) { err.textContent = e.message; }
    }
    function cleanup() { dlg.hidden = true; use.onclick = cancel.onclick = null; document.removeEventListener("keydown", onKey, true); }
    function finish(v) { if (done) return; done = true; cleanup(); resolve(v); }
    function onKey(e) { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); finish(null); } }
    use.onclick = () => finish(cur);
    cancel.onclick = () => finish(null);
    document.addEventListener("keydown", onKey, true);
    dlg.hidden = false;
    load(cur);
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
               : nodeAct("unlock", "unlocked", "lock vault", () => lockVault(v.name)),
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
  state.scope = { vault: name, project: "", env: "" };
  state.open.vaults.add(name); state.view = "projects";
  await renderTree(); renderContent();
}
async function navProject(vault, project) {
  state.scope = { vault, project, env: "" };
  state.open.vaults.add(vault); state.open.projects.add(vault + "/" + project); state.view = "envs";
  await renderTree(); renderContent();
}
async function selectScope(vault, project, env) {
  state.scope = { vault, project, env }; state.view = "entries";
  await renderTree(); await loadEntries();
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
    `Delete the entire vault “${name}” and all its projects, envs and secrets?\nThis cannot be undone.`);
  if (!c) return;
  try {
    await apiWithAuth("POST", "/api/vault/delete", { name, password: c.password }, name); toast("deleted vault " + name);
    if (state.scope.vault === name) { state.scope = { vault: "", project: "", env: "" }; $("#content-body").innerHTML = ""; $("#crumbs").innerHTML = ""; }
    await renderTree();
  } catch (e) { toast(e.message, true); }
}
async function deleteProject(vault, name) {
  const c = await confirmDelete(vault, "Delete project",
    `Delete project “${name}” and all its envs and secrets in ${vault}?`);
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
    `Delete env “${name}” and its secrets in ${vault}/${project}?`);
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
function browse(view) { state.view = view; renderContent(); }

// leaveOverlayView returns from the audit/trust overlay to the most specific
// normal view the current scope supports.
function leaveOverlayView() {
  if (state.scope.env) { state.view = "entries"; loadEntries(); return; }
  if (state.scope.project) { state.view = "envs"; renderContent(); return; }
  if (state.scope.vault) { state.view = "projects"; renderContent(); return; }
  state.view = "entries"; renderContent();
}

function renderContent() {
  renderCrumbs();
  if (state.view === "audit") return renderAuditView();
  if (state.view === "trust") return renderTrustView();
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
  state.view = "audit"; renderContent();
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
  return d.toLocaleString();
}

// ---- trust list view ----------------------------------------------------

function toggleTrust() {
  if (state.view === "trust") { leaveOverlayView(); return; }
  state.view = "trust"; renderContent();
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
    const btn = el("button", "btn btn-ghost sm", "revoke");
    btn.onclick = () => revokeTrust(t.path);
    row.appendChild(btn);
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
// overwritten). Requires the vault unlocked (writes need the key).
async function importEnv() {
  const s = state.scope;
  if (!s.env) { toast("pick an env first", true); return; }
  if (vaultLocked(s.vault)) { toast("unlock the vault to import", true); return; }
  const r = await openDialog({
    title: "Import .env", okText: "import",
    message: `Paste KEY=value lines into ${s.vault}/${s.project}/${s.env}. Existing keys are overwritten.`,
    fields: [{ key: "text", label: "env text", type: "textarea", placeholder: "API_KEY=sk-...\nDB_URL=postgres://..." }],
  });
  if (!r || !r.text.trim()) return;
  await applyImport(parseDotenv(r.text));
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
  if (vaultLocked(state.scope.vault)) {
    const b = el("div", "locked-banner");
    b.appendChild(el("span", null, "🔒 unlock vault to see values"));
    const u = el("button", "btn btn-ghost sm", "unlock");
    u.onclick = () => unlockVault(state.scope.vault);
    b.appendChild(u);
    box.appendChild(b);
  } else if (state.scope.env) {
    const bar = el("div", "entry-tools");
    const imp = el("button", "btn btn-ghost sm", "import");
    imp.title = "import KEY=value lines (or drag a .env file here)"; imp.onclick = importEnv;
    const exp = el("button", "btn btn-ghost sm", "export");
    exp.title = "download this env as a .env file"; exp.onclick = exportEnv;
    bar.appendChild(imp); bar.appendChild(exp);
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
  row.appendChild(el("span", "bdg" + (bd ? " " + bd.cls : ""), bd ? bd.glyph : ""));
  const name = el("span", "cell name", s.name);
  if (!inherited) { name.title = "double-click to rename"; name.ondblclick = (e) => { e.stopPropagation(); editName(s, name); }; }
  else { name.title = "inherited from default"; }
  row.appendChild(name);
  const val = el("span", "cell val"); val.appendChild(maskDots());
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
  if (!inherited) acts.appendChild(iconBtn("trash", "danger", "delete", () => doDelete(s)));
  row.appendChild(acts);
  return row;
}
function maskDots() { return el("span", "mask", "•••••••••"); }

async function revealValue(s) {
  const env = s.source === "default" ? "default" : state.scope.env;
  const data = await apiWithAuth("POST", "/api/entry/reveal",
    { scope: { vault: state.scope.vault, project: state.scope.project, env }, name: s.name },
    state.scope.vault);
  return data.value;
}
async function reveal(s, valEl) {
  try {
    const value = await revealValue(s);
    valEl.classList.add("revealed"); valEl.textContent = value;
    clearTimeout(state.revealTimers[s.name]);
    state.revealTimers[s.name] = setTimeout(() => hideReveal(s, valEl), 10000);
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
  try { const value = await revealValue(s); await navigator.clipboard.writeText(value); toast("copied " + s.name); }
  catch (e) { toast(e.message || "copy failed", true); }
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
// generateByn pins the current scope (and a chosen exec allowlist) into a
// project directory's .byn, optionally trusting it on the spot.
async function generateByn() {
  const sc = curScope();
  if (state.view !== "entries" || !sc.env) { toast("pick a scope first", true); return; }
  const vars = (state.entries || []).map((e) => e.name);
  const r = await openDialog({
    title: "Create .byn",
    message: `Pin ${sc.vault}/${sc.project}/${sc.env} into a project directory's .byn.`,
    okText: "write .byn",
    fields: [
      { key: "dir", label: "project directory", placeholder: "/path/to/project", type: "path" },
      { key: "vars", label: "exec allowlist — vars byn exec may inject", type: "checklist", options: vars },
      { key: "trust", label: "trust now (so byn exec works immediately)", type: "checkbox" },
    ],
    validate: (v) => v.dir ? null : "a project directory is required",
  });
  if (!r) return;

  // Trust is passkey-first: if a passkey can authorize, a single ceremony does
  // it. Otherwise (no passkey, or the user cancels it) fall back to the master
  // password. Either credential is requested ONLY when "trust now" is checked.
  let trust = false, password = "", presence = "";
  if (r.trust) {
    presence = (await tryPasskeyPresence(sc.vault)) || "";
    if (presence) {
      trust = true;
    } else {
      const pw = await openDialog({
        title: "Trust this .byn",
        message: `Enter your master password to trust ${r.dir}/.byn so byn exec can use it.`,
        okText: "trust",
        fields: [{ key: "password", label: "master password", type: "password" }],
        validate: (v) => v.password ? null : "the master password is required to trust",
      });
      if (pw && pw.password) { trust = true; password = pw.password; }
      else { toast("writing .byn without trust (cancelled)", true); }
    }
  }
  try {
    const resp = await api("POST", "/api/byn/write", {
      dir: r.dir, scope: sc, env_vars: r.vars, trust, password, presence_token: presence,
    });
    toast(".byn written → " + resp.path + (resp.trusted ? " · trusted" : ""));
  } catch (e) { toast(e.message, true); }
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

// ---- toast + help -------------------------------------------------------

let toastTimer = null;
function toast(msg, isErr) {
  const t = $("#toast"); t.textContent = msg; t.className = "toast " + (isErr ? "err" : "ok");
  t.hidden = false; clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, isErr ? 4200 : 2000);
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
      message: `Import ${pairs.length} vars from “${file.name}” into ${state.scope.env}? Existing keys are overwritten.` });
    if (!ok) return;
    await applyImport(pairs);
  });
  $("#audit-btn").addEventListener("click", toggleAudit);
  $("#trust-btn").addEventListener("click", toggleTrust);
  $("#byn-btn").addEventListener("click", generateByn);
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
    else if (e.key === "?") { e.preventDefault(); toggleHelp(); }
    else if (e.key === "Escape") hideHelp();
  });
}

async function boot() {
  wire();
  $("#app").hidden = false;
  await renderTree();
  startStatusSync();
  if (state.vaults.length) {
    const first = state.vaults[0].name;
    state.open.vaults.add(first);
    await selectScope(first, "default", "default");
  } else {
    $("#content-body").innerHTML = "";
    const e = el("div", "empty");
    e.appendChild(el("span", "big", "no vaults yet"));
    e.appendChild(document.createTextNode("create one with the + button, top-left"));
    $("#content-body").appendChild(e);
  }
}

boot();
