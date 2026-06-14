# Research spike — WebAuthn PRF for passkey vault-unlock

**Date:** 2026-06-03 · **For:** Phase 2 Slice A-auth · **Status:** spike
complete, verdict = feasible (macOS), build it as a secondary unlock path.

This is a research artifact (web sources, early-2026). It informs the
A-auth design. It is NOT a contract — the
SPEC §12 contract is written when A-auth ships.

---

## Verdict

Feasible **today** for the primary target — macOS Touch ID / iCloud
Keychain passkey via a browser at `http://localhost` (Safari 18+, Chrome
132+, Firefox 139+ on macOS 15+). `http://localhost` is a valid secure
context and `rp.id = "localhost"` is permitted (HTTPS-requirement
carve-out). Build it, but **only as a secondary unlock path** — the master
password stays the durable root/recovery credential. Linux is materially
weaker (no platform authenticator with PRF; needs a roaming `hmac-secret`
hardware key on Chromium, or password fallback).

---

## Browser / OS support matrix

PRF = WebAuthn `prf` extension (built on CTAP2 `hmac-secret`). "Works" =
a deterministic 32-byte output at assertion.

| Platform / Authenticator | Chrome/Edge | Safari | Firefox | Notes |
|---|---|---|---|---|
| **macOS — Touch ID / iCloud passkey** | ✅ 132+ | ✅ 18+ (macOS 15+) | ✅ 139+ | byn's sweet spot. Apple can return first PRF output at `create()`. |
| **Windows — Hello platform passkey** | ✅ 147+ (`WEBAUTHN_API_VERSION_8`) | ❌ | ✅ 148+ | Also needs Win11 25H2 + Feb-2026 KB5077181. Win10: none. |
| **Android — GPM passkey** | ✅ | n/a | ❌ | Most robust overall (not a byn target). |
| **Roaming key (YubiKey 5, `hmac-secret`)** | ✅ Chromium | ⚠️ broken on Safari (returns null/undecryptable for USB/NFC keys) | ⚠️ partial | Apple **platform** authenticators unaffected; bug is external-key-specific. |
| **Linux — platform authenticator** | ❌ none exists | n/a | ❌ | "The browser expects something that doesn't exist." |
| **Linux — roaming key (`hmac-secret` USB/NFC)** | ⚠️ CTAP works; browser exposure inconsistent | n/a | ⚠️ | libfido2/CTAP works (age-plugin uses it); browser PRF unreliable. |

**RP ID:** use `rp.id = "localhost"` — NOT `127.0.0.1` (IPs are invalid RP
IDs) and NOT `localhost:2967` (the port is not part of the RP ID). Pick the
RP ID once and keep it stable: passkeys are bound to it, so moving the
portal off `localhost` later would orphan every enrolled passkey.

---

## Go library support

`github.com/go-webauthn/webauthn` (maintained Duo fork) does **not** type
PRF. Client extension outputs are `AuthenticationExtensionsClientOutputs =
map[string]any`; only `appid`/`appidExclude` are named. So byn must:
- **Registration:** inject `{"prf": {}}` (or `{"prf":{"eval":{"first":<salt>}}}`)
  into `PublicKeyCredentialCreationOptions.Extensions` (passes through as a
  raw map).
- **Assertion:** the 32-byte PRF output is computed **in the browser** and
  read client-side via `getClientExtensionResults().prf.results.first`. The
  **daemon never receives the raw PRF secret.** Use go-webauthn's
  `ValidateLogin` for the *authentication* decision; do the key-recovery
  (unwrap) as a logically separate step. Treat any server-visible
  `prf.enabled` as an untrusted hint, not an auth signal.

---

## Recommended implementation pattern

How `prf` maps to `hmac-secret` (so we store the right thing): the browser
computes `actualSalt = SHA-256("WebAuthn PRF" ‖ 0x00 ‖ ourSalt)`; the
authenticator returns `HMAC(CredRandom, actualSalt)` — per-credential,
per-RP-ID, stable 32 bytes. **`hmac-secret` MUST be enabled at `create()`**
— a credential made without it can never do PRF.

**Enrollment (once, only while the vault is already unlocked):**
1. Vault unlocked via password → daemon holds raw 256-bit vault key `VK`.
2. Register a passkey: `rp.id="localhost"`, `extensions:{prf:{}}`. Confirm
   `getClientExtensionResults().prf.enabled === true`, else abort (no
   passkey-unlock on this browser/authenticator).
3. Generate random 32-byte PRF salt `S` for this credential.
4. Assertion (or eval-at-create on Apple) with `prf:{eval:{first:S}}` →
   `prfOut` (32 B) in the browser.
5. `KEK = HKDF-SHA256(ikm=prfOut, salt="", info="byn:passkey-kek:v1")`.
6. `wrapped = AEAD_Seal(KEK, VK)` (XChaCha20-Poly1305, matching byn's
   stack). The password-wrapped `VK` is untouched — this is purely an
   additional wrapping, so vault data is never re-encrypted (same shape as
   byn's password-change re-wrap).

**Storage** — new SQLite table `passkey_unlock`, one row per credential.
All columns are non-secret (security rests on possession of the
authenticator + user verification):
`credential_id`, `prf_salt` (32 B), `wrapped_vault_key` (nonce ‖ ct ‖ tag),
`hkdf_info_version`, `aead_alg`, `created_at`, `label`.

**Unlock (later sessions):** daemon issues a challenge with
`allowCredentials=[credential_id]`, `prf:{eval:{first:S}}` → browser
assertion (Touch ID) → `prfOut` → `KEK` → unwrap `wrapped_vault_key` → `VK`.
Either the browser unwraps and POSTs `VK` over the loopback socket, or it
sends `prfOut`/`KEK` and the daemon unwraps in Go (preferred — keeps crypto
in one place). The PRF secret never leaves the local machine.

---

## Fallback when PRF absent

1. **Capability probe** with `PublicKeyCredential.getClientCapabilities()`
   (`caps.extensions?.includes("prf")`) before offering passkey-unlock.
2. **Hard-gate enrollment** on `prf.enabled === true` — never enroll a
   passkey for *unlock* if PRF didn't actually enable.
3. **Password stays root/recovery** — password-wrapped `VK` always present;
   losing/deleting the passkey never locks the user out. Enforce
   "password is set" as an invariant BEFORE allowing passkey enrollment
   (no passkey-only access to a vault, ever).
4. **Degrade to passkey-as-session-only:** if PRF is absent, a passkey may
   still authorize a session *after* a password unlock (2FA / MFA step-up
   for sensitive shims), but does not itself recover `VK`.

---

## Gotchas

1. **PRF must be enabled at credential creation** — non-negotiable; a
   passkey registered without `{prf:{}}` is permanently PRF-incapable.
2. **Lose the passkey → that unlock path is irrecoverable** — fine only
   because the password is the recovery root. Enforce password-set first.
3. **`rp.id` must be `localhost`** (stable, no IP, no port) — changing it
   orphans all passkeys.
4. **Safari + external security keys is broken; Linux platform PRF doesn't
   exist** — probe, don't assume; route Linux to roaming `hmac-secret` keys
   on Chromium or to password.
5. **Stable salt + HKDF domain separation** — store a fixed per-credential
   salt (a random salt per unlock would change the KEK and fail to unwrap);
   fold PRF output through HKDF with a fixed `info` string, never use it as
   the key directly. Expect a possible double Touch-ID prompt at enrollment.

---

## Sources

- Corbado — passkeys PRF/WebAuthn support overview: https://www.corbado.com/blog/passkeys-prf-webauthn
- Yubico — Developer's Guide to PRF: https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html
- Yubico — CTAP2 hmac-secret deep dive: https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/CTAP2_HMAC_Secret_Deep_Dive.html
- Filippo Valsorda — passkey encryption / age: https://words.filippo.io/passkey-encryption/
- age-plugin-fido2-hmac spec v2: https://github.com/olastor/age-plugin-fido2-hmac/blob/main/docs/spec-v2.md
- Bitwarden — PRF vault-key design: https://contributing.bitwarden.com/architecture/deep-dives/passkeys/implementations/relying-party/prf/
- SimpleWebAuthn — PRF guide: https://simplewebauthn.dev/docs/advanced/prf
- Vitor Py — Linux TPM FIDO2 PRF gap: https://vitorpy.com/blog/2025-12-25-confer-to-linux-tpm-fido2-prf/
- go-webauthn — protocol/extensions + PRF tracking issue #123: https://github.com/go-webauthn/webauthn
- web.dev — RP ID deep dive (localhost valid, IPs invalid): https://web.dev/articles/webauthn-rp-id
- MDN — WebAuthn extensions (`prf`): https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions

**Uncertainties to verify on real hardware before shipping a claim:**
go-webauthn may still be untyped for PRF (read the raw map); Windows Hello
PRF needs both browser ≥147/148 AND the Feb-2026 OS patch; Linux roaming-key
PRF in-browser varies by distro/browser.
