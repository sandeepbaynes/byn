// passkey.js — portal WebAuthn (Touch ID / passkey) glue.
//
// Self-contained: exposes window.bynPasskey and wires a small panel off the
// header #passkey-btn, without touching app.js. The cryptography lives in the
// daemon; this file only (a) base64url-codes the binary fields the WebAuthn
// API needs and (b) calls the /api/passkey/* endpoints.
//
// rp.id is "localhost" (daemon-fixed), so the portal must be reached at
// http://localhost:<port> — a 127.0.0.1 URL will fail the RP-ID check.
(function () {
  "use strict";

  // ---- base64url <-> ArrayBuffer -----------------------------------------
  function b64urlToBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }
  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function bufToB64std(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin); // base64-std (padded) — matches a Go []byte JSON field (the KEK)
  }

  // HKDF-SHA256(prfOut) -> 32-byte KEK, domain-separated. The info string is
  // part of the contract with the daemon and must not change.
  async function hkdfKEK(prfBuf) {
    const ikm = await crypto.subtle.importKey("raw", prfBuf, "HKDF", false, ["deriveBits"]);
    return crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new TextEncoder().encode("byn:passkey-kek:v1") },
      ikm, 256); // ArrayBuffer, 32 bytes
  }

  // The PRF output from a create()/get() result, or null if PRF didn't run.
  function readPRF(cred) {
    const ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
    const r = ext && ext.prf && ext.prf.results && ext.prf.results.first;
    return r || null; // ArrayBuffer | null
  }

  // prfSupported probes the browser's WebAuthn client capabilities for PRF.
  // Returns true/false, or null when the capability API is unavailable.
  async function prfSupported() {
    try {
      if (window.PublicKeyCredential && PublicKeyCredential.getClientCapabilities) {
        const caps = await PublicKeyCredential.getClientCapabilities();
        if (typeof caps["extension:prf"] === "boolean") return caps["extension:prf"];
        if (caps.extensions && caps.extensions.includes) return caps.extensions.includes("prf");
      }
    } catch (e) { /* capability probe unsupported */ }
    return null;
  }

  // ---- API ---------------------------------------------------------------
  async function api(path, body) {
    const opt = { headers: { "Content-Type": "application/json" } };
    // Every /api/passkey/* route is requireToken-gated, so attach the portal
    // owner-token exactly like app.js's api(). Read localStorage directly (key
    // "byn.portal_token") so this file stays self-contained. Without this the
    // daemon answers 401 "portal_token_required" and enroll/auth fail.
    const tok = localStorage.getItem("byn.portal_token") || "";
    if (tok) opt.headers["X-Byn-Portal-Token"] = tok;
    if (body !== undefined) {
      opt.method = "POST";
      opt.body = JSON.stringify(body);
    }
    const res = await fetch(path, opt);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
    return data;
  }

  // ---- options decoding (server base64url -> ArrayBuffers) ---------------
  function decodeCreation(pub) {
    pub.challenge = b64urlToBuf(pub.challenge);
    pub.user.id = b64urlToBuf(pub.user.id);
    (pub.excludeCredentials || []).forEach((c) => { c.id = b64urlToBuf(c.id); });
    const ev = pub.extensions && pub.extensions.prf && pub.extensions.prf.eval;
    if (ev && ev.first) ev.first = b64urlToBuf(ev.first);
    return pub;
  }
  function decodeRequest(pub) {
    pub.challenge = b64urlToBuf(pub.challenge);
    (pub.allowCredentials || []).forEach((c) => { c.id = b64urlToBuf(c.id); });
    const prf = pub.extensions && pub.extensions.prf;
    if (prf) {
      if (prf.eval && prf.eval.first) prf.eval.first = b64urlToBuf(prf.eval.first);
      if (prf.evalByCredential) {
        Object.keys(prf.evalByCredential).forEach((k) => {
          const e = prf.evalByCredential[k];
          if (e && e.first) e.first = b64urlToBuf(e.first);
        });
      }
    }
    return pub;
  }

  // ---- response encoding (Credential -> server JSON, base64url) ----------
  function encodeAttestation(cred) {
    const r = cred.response;
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(r.clientDataJSON),
        attestationObject: bufToB64url(r.attestationObject),
      },
    };
  }
  function encodeAssertion(cred) {
    const r = cred.response;
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(r.clientDataJSON),
        authenticatorData: bufToB64url(r.authenticatorData),
        signature: bufToB64url(r.signature),
        userHandle: r.userHandle ? bufToB64url(r.userHandle) : null,
      },
    };
  }

  // ---- ceremonies --------------------------------------------------------
  async function enroll(vault, label) {
    const begin = await api("/api/passkey/register/begin", { vault });
    const opts = typeof begin.options === "string" ? JSON.parse(begin.options) : begin.options;
    const pub = decodeCreation(opts.publicKey);
    const saltBuf = pub.extensions && pub.extensions.prf && pub.extensions.prf.eval && pub.extensions.prf.eval.first;
    const cred = await navigator.credentials.create({ publicKey: pub });
    const body = { vault, ceremony_id: begin.ceremony_id, response: encodeAttestation(cred), label: label || "" };
    // Obtain the PRF output: from create() if the authenticator evaluated it
    // there, otherwise via an immediate assertion with the same salt (a second
    // Touch ID prompt). Without it the passkey is sign-in only.
    let prf = readPRF(cred);
    if (!prf && saltBuf) prf = await evalPRF(cred.rawId, saltBuf);
    if (prf) body.kek = bufToB64std(await hkdfKEK(prf));
    return api("/api/passkey/register/finish", body);
  }

  // evalPRF does a local assertion against credId purely to extract the PRF
  // output (the daemon never sees this assertion — it's key derivation only).
  async function evalPRF(rawId, saltBuf) {
    try {
      const assertion = await navigator.credentials.get({ publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: "localhost",
        allowCredentials: [{ type: "public-key", id: rawId }],
        userVerification: "required",
        extensions: { prf: { eval: { first: saltBuf } } },
      } });
      return readPRF(assertion);
    } catch (e) { return null; }
  }

  async function signIn(vault) {
    const begin = await api("/api/passkey/auth/begin", { vault });
    const opts = typeof begin.options === "string" ? JSON.parse(begin.options) : begin.options;
    const publicKey = decodeRequest(opts.publicKey);
    const cred = await navigator.credentials.get({ publicKey });
    const prf = readPRF(cred);
    const body = { vault, ceremony_id: begin.ceremony_id, response: encodeAssertion(cred) };
    // If PRF ran, derive the KEK so the daemon can unwrap + unlock the vault.
    if (prf) body.kek = bufToB64std(await hkdfKEK(prf));
    return api("/api/passkey/auth/finish", body);
  }

  function list(vault) {
    return api("/api/passkey/list?vault=" + encodeURIComponent(vault || ""));
  }
  function remove(vault, credentialId, password) {
    return api("/api/passkey/remove", { vault, credential_id: credentialId, password });
  }
  function session() {
    return api("/api/passkey/session");
  }
  // canUnlock reports whether vault has at least one passkey that can cold-unlock
  // it (vs session-only) — so the UI only prompts Touch ID when it will work.
  async function canUnlock(vault) {
    try {
      const r = await list(vault);
      return (r.passkeys || []).some((p) => p.unlock);
    } catch (e) { return false; }
  }

  window.bynPasskey = { enroll, signIn, list, remove, session, canUnlock, b64urlToBuf, bufToB64url };

  // ---- minimal panel (no app.js coupling) --------------------------------
  function currentVault() {
    // app.js keeps the selected scope in a top-level `state` (classic scripts
    // share one global lexical scope); fall back to "default".
    try {
      if (typeof state !== "undefined" && state && state.scope && state.scope.vault) return state.scope.vault;
    } catch (e) { /* app.js not loaded */ }
    return "default";
  }

  function panelHTML() {
    return (
      '<div class="pk-modal" role="dialog" aria-modal="true">' +
      '<div class="pk-card">' +
      '<div class="pk-head"><h2>Passkeys &amp; Touch&nbsp;ID</h2>' +
      '<button id="pk-close" class="pk-x" type="button" aria-label="close">×</button></div>' +
      '<p class="pk-sub">vault&nbsp;<code id="pk-vault"></code></p>' +
      '<div id="pk-list" class="pk-list"></div>' +
      '<div class="pk-actions">' +
      '<button id="pk-enroll" class="btn btn-primary pk-full" type="button">Add passkey</button>' +
      "</div>" +
      '<p class="pk-hint">To unlock a locked vault with Touch&nbsp;ID, use its unlock action in the sidebar.</p>' +
      '<div id="pk-msg" class="pk-msg"></div>' +
      "</div></div>"
    );
  }

  function open() {
    if (!window.PublicKeyCredential) {
      alert("This browser has no WebAuthn support.");
      return;
    }
    const vault = currentVault();
    const host = document.createElement("div");
    host.innerHTML = panelHTML();
    document.body.appendChild(host);
    host.querySelector("#pk-vault").textContent = vault;
    const msg = host.querySelector("#pk-msg");
    const say = (t, err) => { msg.textContent = t; msg.className = "pk-msg" + (err ? " err" : ""); };
    const close = () => host.remove();

    async function refresh() {
      try {
        const r = await list(vault);
        const items = (r.passkeys || []);
        const box = host.querySelector("#pk-list");
        box.textContent = "";
        if (!items.length) {
          const e = document.createElement("div");
          e.className = "pk-empty";
          e.textContent = "no passkeys enrolled";
          box.appendChild(e);
          return;
        }
        // Build rows with textContent — p.label is user-controlled (set at
        // enrollment), so it must never reach innerHTML.
        items.forEach((p) => {
          const row = document.createElement("div");
          row.className = "pk-row";
          const left = document.createElement("div");
          left.className = "pk-rowleft";
          const span = document.createElement("span");
          span.className = "pk-label";
          span.textContent = p.label || "passkey";
          const badge = document.createElement("span");
          badge.className = "pk-badge" + (p.unlock ? " ok" : "");
          badge.textContent = p.unlock ? "unlocks" : "sign-in only";
          left.appendChild(span);
          left.appendChild(badge);
          const rev = document.createElement("button");
          rev.className = "pk-revoke";
          rev.type = "button";
          rev.textContent = "revoke";
          rev.onclick = async () => {
            // byn's own masked dialog — never window.prompt() (shows the
            // master password in plaintext).
            if (typeof openDialog !== "function") { say("password dialog unavailable", true); return; }
            const r = await openDialog({
              title: "Revoke passkey",
              okText: "revoke",
              danger: true,
              message: "Enter your master password to revoke “" + (p.label || "passkey") + "”.",
              fields: [{ key: "password", label: "master password", type: "password" }],
            });
            if (!r || !r.password) return;
            say("revoking…");
            try { await remove(vault, p.credential_id, r.password); say("passkey revoked."); refresh(); }
            catch (e) { say("revoke failed: " + e.message, true); }
          };
          row.appendChild(left);
          row.appendChild(rev);
          box.appendChild(row);
        });
      } catch (e) { say(e.message, true); }
    }

    host.querySelector("#pk-close").onclick = close;
    host.querySelector(".pk-modal").addEventListener("click", (e) => {
      if (e.target === e.currentTarget) close(); // click backdrop to dismiss
    });
    host.querySelector("#pk-enroll").onclick = async () => {
      say("follow the prompt(s)… (choose iCloud Keychain to enable unlock)");
      try {
        const r = await enroll(vault, "Touch ID");
        if (r && r.unlock) {
          say("passkey enrolled — it unlocks this vault.");
        } else {
          say("enrolled, but sign-in only: this authenticator has no PRF. Re-create it in iCloud Keychain — in Chrome's save dialog pick “iCloud Keychain”, not “Chrome profile” — or use Safari.", true);
        }
        refresh();
      } catch (e) { say("enroll failed: " + e.message, true); }
    };
    // Surface whether the browser advertises PRF at all (logged in full too).
    prfSupported().then((ok) => {
      if (ok === false) say("heads-up: this browser reports no PRF support — passkey unlock won't be available here.", true);
    });
    refresh();
  }

  function injectStyles() {
    const css =
      ".pk-modal{position:fixed;inset:0;background:rgba(0,0,0,.62);backdrop-filter:blur(2px);display:flex;align-items:center;justify-content:center;z-index:1000}" +
      ".pk-card{background:#16181d;border:1px solid #2a2e37;border-radius:12px;padding:22px 24px 20px;width:min(440px,92vw);color:#e6e6e6;box-shadow:0 24px 60px rgba(0,0,0,.5)}" +
      ".pk-head{display:flex;align-items:center;justify-content:space-between;gap:12px}" +
      ".pk-card h2{margin:0;font-size:17px;font-weight:650;letter-spacing:.2px}" +
      ".pk-x{background:none;border:0;color:#9aa0aa;font-size:22px;line-height:1;cursor:pointer;padding:0 4px}" +
      ".pk-x:hover{color:#e6e6e6}" +
      ".pk-sub{margin:6px 0 16px;color:#9aa0aa;font-size:13px}" +
      ".pk-sub code{background:#22262e;padding:2px 7px;border-radius:5px;color:#cfe3ff}" +
      ".pk-list{margin:0 0 16px;display:flex;flex-direction:column;gap:7px}" +
      ".pk-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:9px 12px;background:#1b1e25;border:1px solid #2a2e37;border-radius:8px;font-size:13px}" +
      ".pk-rowleft{display:flex;align-items:center;gap:8px;overflow:hidden}" +
      ".pk-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}" +
      ".pk-badge{font-size:10px;padding:2px 6px;border-radius:4px;background:#2a2e37;color:#9aa0aa;white-space:nowrap}" +
      ".pk-badge.ok{background:#15301f;color:#7fdca0}" +
      ".pk-revoke{background:none;border:1px solid #44303a;color:#ff9a9a;font-size:12px;padding:3px 10px;border-radius:6px;cursor:pointer}" +
      ".pk-revoke:hover{background:#2a1c20;border-color:#6a3a44}" +
      ".pk-empty{color:#777;font-size:13px;padding:10px 0;text-align:center}" +
      ".pk-actions{display:flex;flex-direction:column;gap:9px}" +
      ".pk-full{width:100%;justify-content:center}" +
      ".pk-msg{margin-top:14px;font-size:13px;color:#8fb8ff;min-height:18px;text-align:center}" +
      ".pk-msg.err{color:#ff8f8f}" +
      ".pk-hint{margin-top:14px;font-size:12px;color:#6b7280;text-align:center;line-height:1.45}";
    const style = document.createElement("style");
    style.textContent = css; // static CSS, no untrusted content
    document.head.appendChild(style);
  }

  document.addEventListener("DOMContentLoaded", function () {
    injectStyles();
    const btn = document.getElementById("passkey-btn");
    if (btn) btn.addEventListener("click", open);
  });
})();
