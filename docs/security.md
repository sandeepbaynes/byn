# Security model

What byn defends against, how, and what it deliberately doesn't.

---

## Why byn exists: owned by you, operated by many

Endpoint security — and Trust On First Use with it — was built on one
assumption: that code running under your account is *you*. That held for
decades, because the only things running as you were programs you
personally launched.

It's now false. Your machine is owned by one human and **operated by a
crowd** — coding agents, MCP servers, CI runners, package post-install
scripts, browser extensions, background helpers — each acting under your
UID, none of them you. The PC stopped being personal; it became a shared
execution substrate where you don't know every actor by name.

This breaks **authority-by-identity**. UNIX grants power by *who* you are
(your UID), but your UID is now a shared identity, so it is no longer a
trust signal. A "trust this? [y/n]" prompt assumes a human answers — yet
the agent that triggered it controls the same terminal. It is the
**confused-deputy problem at machine scale**: the daemon holds your
authority and cannot tell the owner from an operator.

byn's response is to move trust from *identity* to *proof of intent*:

- **Ambient authority is the hazard.** An unlocked vault is power any
  same-UID actor can draw on — so sensitive actions (granting trust,
  revealing values, destructive ops) demand fresh proof-of-presence, not
  an already-unlocked session.
- **Consent must arrive on a channel the crowd can't drive.** A password
  typed at a TTY the agent controls is not proof of *you*. The strong
  form routes approval out-of-band — a biometric tap, the browser portal
  as a separate origin, an OS secure prompt.
- **Consent is scoped and rare.** Each approval binds to a specific
  file / hash / scope so a blind "yes" can't be replayed, and the human
  is asked seldom enough that the ask still carries weight.

**The honest ceiling:** none of this is absolute while the adversary
shares your UID — a process running as you can ptrace the daemon, keylog
the prompt, or read its memory (see *Out of scope* below). byn's job is
to make that gap **small and loud**; closing it to zero needs OS-level
isolation (agents on their own UID/sandbox) and hardware-rooted prompts
(Secure Enclave / TPM), not just a daemon. byn raises the bar as far as
user space can, and is explicit about where the kernel and hardware must
take over.

---

## Threat model

We protect a user's secrets against the following adversaries.

### In scope

| Adversary | What they have | What we prevent |
|---|---|---|
| **Another local user** on a shared machine | Their own UID's permissions | Reading or modifying our vault, our socket, our audit log. Enforced by file modes (0600) and peer-UID check on the socket. |
| **A passive thief** with `vault.db` | A copy of the encrypted DB | Reading any secret. Without the password + machine fingerprint, the vault key is unrecoverable. |
| **A shoulder-surfer** of the user's terminal | Visual access to scrollback, history, `ps` | Seeing secret values — they never appear in argv, environment, prompts, history, or scrollback. |
| **A careless or semi-trusted agent** (coding agent, evil VSCode extension, compromised CI) running as the user | Can run `byn` commands | (a) **Detection over prevention:** a same-UID agent *can* invoke `get`/`exec`, so the guarantee is that **every value access is audited** (`byn audit`) — harness deny rules are best-effort and not relied upon. The primary win is that there is no plaintext `.env` on disk to read accidentally. (b) `byn exec` injects vars only into the child it spawns; the parent shell sees nothing — but the child's own `/proc/<pid>/environ` is readable by a same-UID process, so env values reach the workload (this is an accepted limitation, not concealment from it). (c) Untrusted `.byn` files hard-fail in agent mode (`--json`) so the agent can't be silently redirected. |
| **IDE code-completion / inline-suggestion models** (Copilot, Cursor Tab, JetBrains AI, …) running as you | A continuous read of your editor buffer + neighbouring tabs, streamed to (usually cloud) inference on every keystroke | A secret typed as a *literal into source* is ingested the instant it lands in the buffer — and with cloud inference it has **already left the machine before you finish the line** (the model suggesting the cred back, or offering to move it, is proof it read it; it may then propagate it into other files/commits). byn's mitigation is structural: secrets live in the vault and are referenced by *name* / injected at runtime via `byn exec`, so there is no literal in the buffer to slurp. byn can't intercept the IDE itself — keeping literals out of source is the control byn makes practical. |
| **A tampering attacker** with write access to `vault.db` or the audit log | Can modify on-disk state without the key | (a) Tampered ciphertext fails AEAD auth → vault refuses to open / decrypt. (b) Tampered audit log fails HMAC chain → `byn audit verify` flags first bad index → daemon error to user. |
| **An attacker with write access to a project directory** | Can plant or modify a `.byn` | TOFU SHA-256 binds trust to specific file contents. A new or changed `.byn` is **refused** — discovery never auto-trusts; approval is a separate, password-gated `byn trust` (proof of presence). A *changed* previously-trusted file is never silently re-trusted. |

### Out of scope

These attackers we acknowledge as breaks; byn is not the right
control surface.

| Adversary | Why we accept this |
|---|---|
| **Root on your machine** | Anyone with root can read your memory, swap, files, signals — game over for any user-space secret manager. |
| **An attacker who knows your master password** | The password is the perimeter. Use a strong one. |
| **An attacker with shell access as your UID** | Can replace the `byn` binary, modify shell init, intercept your password prompt. The vault crypto buys you nothing if the attacker controls the process running the unlock. |
| **A live-memory attacker** (debugger, ptrace) | If the daemon is unlocked when attached to, the vault key is in memory. Defense-in-depth via mlock is best-effort. |
| **A coercion attacker** | "Type your password or else" is not a cryptographic problem. |
| **Network MITM** | byn is local-only today. Phase 6's cloud sync will add TLS + signed payloads. |

### The primary threat: dev-time AI agents reading secret files

byn's main reason to exist is the **careless or semi-trusted coding
agent** row above. The leak vector is the agent reading a plaintext
`.env` / `~/.aws/credentials` / SSH key off disk and echoing it into
chat history, logs, or a commit — silently, so the user may not know
until it's too late. This is externally validated: in-app guardrails
are unreliable (Claude Code `read.deny` failed to block `.env` reads —
[anthropics/claude-code#24846](https://github.com/anthropics/claude-code/issues/24846)),
and a survey of prior art found no tool that combines transparent
injection + keeping plaintext off the agent's disk + a per-access audit
trail (full analysis:
internal design notes).

byn's answer is **reduce-and-detect**: there is no plaintext file to
read, and every value access is audited — so even when prevention
fails, the leak is *detectable*. byn deliberately does NOT rely on the
agent harness enforcing a deny rule. The full per-case guarantee and
accepted limitations (notably env-var `/proc` readability) are the
contract in [spec.md §9.4](spec.md).

### A second silent vector: IDE code-completion

The same leak happens without any agent you invoked. Inline completion
(Copilot, Cursor Tab, JetBrains AI, …) reads your editor buffer on every
keystroke and ships the surrounding context to an inference endpoint to
predict the next tokens. The moment you type a real credential into a
source file, it is in that context — already read, and, if inference is
cloud-hosted, already off the machine. The tell is when autocomplete
**suggests the secret back to you** (or offers to move it onto another
line): that suggestion can only exist because the model ingested the
value. No file was read off disk, no command ran, and you get zero
signal it happened — by the time you notice, the credential has already
been sent to a third party and must be treated as compromised (rotate
it).

byn answers this the same structural way: remove the reason for a
plaintext literal to ever sit in a source buffer. Reference the secret
by name and let `byn exec` inject it at runtime, and there is nothing
for completion to slurp. The honest limit is the same as the IDE row
above — byn cannot police the editor, so if you *do* put a literal in a
file, completion can still see it. "No secret literals in source" is the
discipline byn makes practical, not one it can enforce.

---

## Crypto choices

### 1. Vault key

A fresh 32 random bytes from `crypto/rand` at `byn init`. Lives
**only** in daemon memory while unlocked, wrapped on disk while
locked.

### 2. Key wrapping (Argon2id + AEAD)

```
wrapping_key = Argon2id(
    password   = bytes(master_password),
    salt       = random 16 bytes (per-wrap),
    time       = 4,         // iterations
    memory     = 256 MiB,
    threads    = 4,
    key_length = 32,
)

wrapped.key = XChaCha20-Poly1305-Seal(
    key   = wrapping_key,
    nonce = random 24 bytes,
    plain = vault_key (32 bytes),
    aad   = header_bytes,   // version + salt + Argon2 params + nonce
)
```

**Upper bounds** on Argon2 params: time ≤ 8, memory ≤ 1 GiB, threads ≤ 8.
Prevents DoS via a malicious header.

**Why AAD = full header bytes:** binds every byte of the header
(version, salt, params, nonce) into the auth tag. Flip one bit of the
header → unwrap fails. Stops downgrade attacks (e.g., forcing weaker
Argon2 params) and salt-replacement attacks.

**Why XChaCha20 (24-byte nonce) and not AES-GCM (12 bytes):** random
nonces. With a 12-byte nonce, the birthday bound is ~2^48, which is
visible for long-lived keys. 24 bytes lifts it past anything we
realistically reach.

### 3. Row encryption

Every entry value is AEAD-sealed individually:

```
ciphertext = XChaCha20-Poly1305-Seal(
    key   = vault_key,
    nonce = random 24 bytes,
    plain = value bytes,
    aad   = vault_id || 0x1F || kind || 0x1F || name,
)
```

Stored format: `nonce || ciphertext_with_tag`.

**Why AAD includes vault_id, kind, name:** a row literally cut from
one vault and pasted into another (or one entry's bytes copied onto
another's row) fails to decrypt. This catches both DB-level tampering
and accidental row-swap bugs.

**Why per-row nonces (not deterministic):** two entries with the same
plaintext have unrelated ciphertexts. Also avoids any need for nonce
counters or per-vault sequence state.

### 4. Audit chain

```
hmac_chain_i = HMAC-SHA256(
    seed   = 32 random bytes (stored in vault meta),
    data   = prev_hmac_chain || canonical(event_json),
)
```

Append-only log files at `~/.byn/audit/<vault>/YYYY-MM.log`.
`byn audit verify` walks the chain and reports the first index that
fails — bit-exact detection of any insertion, deletion, or
modification.

**Why HMAC, not a digital signature:** verification is self-contained
(no public-key infra), and we only need to detect tampering by an
attacker who *doesn't have the seed*. The seed is stored encrypted
in the vault meta (cannot be read while locked but the chain head can
still be inspected — `byn audit tail` works locked).

### 5. Failed-unlock backoff

Persistent exponential backoff in `~/.byn/auth-state.json`. After
N failed unlocks: wait `base * multiplier^N` (default base 1s,
multiplier 1.8, capped at 30 min). State survives daemon restart so
an attacker can't just `daemon stop && daemon start` to reset.

**Deferred hardening:** sign this file (HMAC with a daemon-resident
key derived from machine fingerprint) so tampering is detectable.
Today it's protected only by mode 0600 in `~`.

### 6. Hardware-key wrapping (reserved, Slice 1.3)

Provider interface in `internal/hwkey/`:

- **macOS:** Secure Enclave via Security.framework (ECIES wrap of the
  vault key with an SE-resident keypair). Requires entitlements + a
  signed binary; tests skip without.
- **Linux:** TPM2 via tpm2-tss (deterministic seal).
- **Software fallback:** file-backed for portability + CI.

Wired but gated. When live: vault key needs *both* password+Argon2id
*and* an SE/TPM operation, so a stolen `wrapped.key` is useless
without the machine.

### 7. Passkey unlock (WebAuthn PRF)

A passkey (Touch ID / iCloud Keychain) can unlock a vault without typing the
master password — a **second, independent wrapping** of the same vault key:

- **Enrollment** (only while the vault is already unlocked, so the daemon holds
  the key): the browser registers a `localhost` passkey with the WebAuthn `prf`
  extension, evaluates PRF over a random per-credential salt, and derives
  `KEK = HKDF-SHA256(prfOut, info="byn:passkey-kek:v1")`. **The 32-byte PRF
  output never leaves the browser** — only the derived KEK crosses the loopback
  socket. The daemon AEAD-wraps a second copy of the vault key with the KEK
  (XChaCha20-Poly1305, AAD = `vault_id ‖ credential_id ‖ domain`) into the
  `passkey_unlock` table. The password wrap is untouched — **vault data is never
  re-encrypted** (same shape as a password change).
- **Unlock:** the assertion re-evaluates PRF over the stored salt → the same KEK
  → the daemon unwraps the stored copy and installs the key. A wrong KEK,
  tampered ciphertext, or mismatched AAD **fails closed** (the vault stays
  locked); the raw vault key never enters the browser.
- **Per vault, never passkey-only:** each passkey wraps only *its* vault's key
  (bound by AAD + a per-vault user handle). `rp.id` is fixed to `localhost`, so
  macOS groups all byn passkeys under one "site" — but authorization is
  per-vault, server-side. The **master password stays the durable root**:
  enrollment requires a password-set vault, and losing every passkey never
  locks you out.
- **Revoke = lockout:** removing a credential is password-gated and cascades
  (`ON DELETE CASCADE`) to its `passkey_unlock` row, so a revoked passkey can
  never unlock the vault again.
- **Scope:** needs a platform authenticator that implements `prf` — macOS Touch
  ID / iCloud Keychain (Safari, or Chrome with an *iCloud-Keychain* passkey).
  Authenticators without PRF (e.g. Chrome's own Google-Password-Manager
  passkeys) degrade to **session-only** sign-in, never key recovery.

Honest ceiling: convenience + a second unlock path, not a stronger root than the
password. The KEK transits the loopback socket once per unlock, to a daemon that
already holds the key while unlocked; it does not defend against a compromised
daemon or a same-machine attacker who can drive the browser — see "owned by you,
operated by many" above.

---

## Process & IPC defenses

### Unix socket peer-UID enforcement

Socket file is created mode 0600 in `~/.byn/`. Every connection
goes through `internal/daemon/peercred_{darwin,linux}.go`:

- Linux: `SO_PEERCRED` returns UID of peer.
- macOS: `LOCAL_PEEREPID` (effective PID) + getppid lookup; UID
  derived. (peerPID is partial today; documented in PLAN.)

If peer UID ≠ daemon owner UID, the connection is closed
immediately — before reading the request.

**Why:** stops another local user from connecting if file modes were
accidentally loosened (e.g., a chmod typo).

### One envelope per connection

CLI dials, sends one envelope, reads one, closes. No multiplexing →
no risk of cross-request information leaks, and the daemon's
per-request state is implicit. Long-running ops (TUI, future web UI)
will open their own connections.

### Secrets are never in argv

- `byn put NAME VALUE` is rejected with an explicit error: value
  must come from stdin or a heredoc.
- `byn get` writes raw bytes to stdout; trailing newline is added
  only when stdout is a TTY (so `byn get key > file.pem` is
  byte-exact).
- `byn exec` uses `syscall.Exec` to replace the CLI process — no
  parent process inheriting the unwrapped values, no shell variable
  with the secret, no ps line showing it.

### Secrets are never in the shell

`byn exec -- CMD ARGS` builds the env vector and replaces the
process image. The user's interactive shell never sees `KEY=value`;
only the spawned program does.

### mlock'd workspace

`internal/secmem` provides byte buffers that are `mlock`ed (or
best-effort on platforms without it). The daemon uses these for the
master password and the Argon2id work area. Doesn't help against root,
but does help against accidental disk swap on memory pressure.

---

## CLI-level controls

### Agent mode (`--json`)

When `--json` appears anywhere before `--` in argv, byn refuses
to interactively prompt for anything. Specifically:

- Untrusted `.byn` file → hard error (not a y/N prompt).
- Tampered `.byn` file → hard error.

Agents and CI can never silently auto-trust a malicious config.

### Trust-on-First-Use for `.byn`

`~/.byn/trusted_byn.json` maps a canonical path (after
`filepath.EvalSymlinks`) to a SHA-256 of the file's full contents.
Discovery is **read-only**: a new or changed `.byn` is refused (in both
interactive and agent mode) — it never auto-trusts. Approval is a
separate, deliberate act — `byn trust PATH` — which **always requires
the master password** (proof of presence, even when the vault is already
unlocked). The daemon owns the store and verifies the password before
recording. A *changed* previously-trusted file is never silently
re-trusted. See [`.byn` file format](byn-file-format.md).

**The ceiling (honest):** the password gate closes the `byn trust` and
interactive-prompt vectors — an agent constrained to byn's CLI, or one
that doesn't have the password, can no longer grant or re-grant trust.
It does **not** stop a code-executing same-UID process from writing
`trusted_byn.json` directly (mode 0600 in `~` doesn't keep *you* out of
your own file). That's the same user-space ceiling as everywhere here:
*small and loud*, not zero. Tamper-evidence for the store — HMAC-signing
it with a daemon-resident key — is designed and deferred to a **separate
slice**; even then, a same-UID adversary that can recompute the key
isn't fully stopped without OS isolation.

### Hints redaction

`hintf` writes scope path but not values: `Stored "DB_URL" in
maison-agent/staging.` Never `Stored "DB_URL=…" in …`. Set
`BYN_HINTS=0` to suppress even those.

---

## Audit & forensics

- Audit chain is HMAC-signed → tampering detectable but not preventable.
- Plain-text names so investigators see *what* was accessed. The
  trade-off was debated; we landed on forensic value > marginal
  hiding (internal design notes).
- Caller UID + PID captured per event when the OS surfaces them.
  Helps trace which agent or shim made the call.
- `byn doctor` runs verify on every vault's chain at any time.

---

## Deferred hardening

Tracked items, designed but not shipped. Pull forward as the
deployment surface grows.

| Item | Why deferred | When to revisit |
|---|---|---|
| Trust-file HMAC | Realistic attacker who can write `~` already owns more dangerous surfaces | After Slice 7; ~80 LoC; see internal design notes |
| Auth-state signing | Same threat model as trust-file | Together with the trust-file hardening |
| LOCAL_PEEREPID on macOS | Multi-user attacks are out of scope for solo dev box; the existing peer-UID check is sufficient | When byn ships to multi-user servers |
| Constant-time rate-limit responses | Timing oracle on failed-unlock counts is low value (attacker already has the encrypted DB if they can time you) | When byn ships to multi-user servers |
| macOS SE wrapping | Needs dev signing + entitlements + a Mac CI runner | Slice 1.3 (was on the PLAN; deferred for delivery) |
| Linux TPM2 wrapping | Same as SE, plus tpm2-tss is a heavy dep for casual users | Slice 1.3 |
| `--quiet` flag | `BYN_HINTS=0` + shell redirection works | When users ask for it |
| Constant-time `wrong_password` vs vault-not-found | Same response today (existence oracle defense) | If we ever change that |
| **OS deny-read layer** (Seatbelt/Landlock) paired with the shim | A PATH-shim alone is bypassable (abs path, `PATH` rewrite, direct file read); containment needs a kernel deny-read on the cred files. Out of scope pre-public. | Phase 3, when shims land; see internal design notes |
| **Per-operation biometric auth** | Removes the persistent unlock window for value egress, but brutal UX without a biometric tap; revisits the deferred per-read analysis | Post-launch, with Touch ID/WebAuthn; see internal design notes |
| **Fingerprinted exec allowlist** | Only pre-authorized commands get exec rights — strong for sealed tools, defeated for agent-authored interpreters | Phase 3, with shims |
| **Ephemeral scoped credential broker** | Vend short-lived STS tokens via AWS `credential_process` so the durable key never leaves the daemon (Case B cloud creds) | Post-launch; larger scope (cloud integration) |

---

## Related

- [Architecture](architecture.md) — IPC, scope, schema, daemon process model.
- [`.byn` + discovery](byn-file-format.md) — TOFU details.
- [CLI reference](cli-reference.md) — every flag and env var.
