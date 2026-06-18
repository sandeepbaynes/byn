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
| **A passive thief** with `vault.db` | A copy of the encrypted DB | Reading any secret **value**. Values are AEAD-encrypted under the vault key, and the vault key is wrapped with `Argon2id(master password)` — **the password is the only barrier**. The vault file is deliberately **portable** (no machine binding — an owner decision so forensics/recovery work on other hardware), so a thief can mount an offline guessing attack at leisure; Argon2id (default 64 MiB / time=2, ~1s on the *defender's* laptop) slows each guess, but it is not a high wall against a funded attacker with GPUs/ASICs, and a weak password falls regardless. **What the file does NOT hide:** entry/project/env *names*, timestamps, version counts, and file metadata are readable from the DB without any key (an accepted trade-off — see "Audit & forensics" below); and the audit chain's HMAC seed travels in the file, so the *thief's copy* of the log can be silently rewritten (off-box anchoring is the planned fix). A generated break-glass recovery key that replaces the memorable password as the portability root is planned (PH-1). **One scoped exception to "the password is the only barrier":** vars that a trusted `.byn` has allowlisted for *autonomous (password-free) exec* are additionally recoverable **on the original machine** via a machine-fingerprint-wrapped capability stored in the trust record (see "Known limitations" and "Row encryption") — for those specific vars, machine + service-user isolation is the at-rest floor, not the password. Every other value stays password-only at rest. |
| **A shoulder-surfer** of the user's terminal | Visual access to scrollback, history, `ps` | Seeing secret values — they never appear in argv, environment, prompts, history, or scrollback. |
| **A careless or semi-trusted agent** (coding agent, evil VSCode extension, compromised CI) running as the user | Can run `byn` commands | (a) **Detection over prevention:** a same-UID agent *can* invoke `get`/`exec`, so the guarantee is that **every value access is audited** (`byn audit`) — harness deny rules are best-effort and not relied upon. The primary win is that there is no plaintext `.env` on disk to read accidentally. (b) `byn exec` injects vars only into the child it spawns; the parent shell sees nothing. With **`[security] privsep` enabled** (opt-in this release; set up via `byn setup`), a trusted-`.byn` *pinned* exec runs its child as the dedicated `_byn-exec` service user, so a same-(owner)-UID **non-root** process **cannot** read the child's `/proc/<pid>/environ` (the kernel's ptrace-mode check denies a cross-uid read) — verified by the privsep integration test. **Honest ceiling:** root / `CAP_SYS_PTRACE` can still read that environ — that is the documented limit. With privsep **off (the default)**, or for **ad-hoc exec** (no `.byn`), the child runs in-process as the owner and a same-UID process *can* read its environ (an accepted limitation, not concealment from it). (c) Untrusted `.byn` files hard-fail in agent mode (`--json`) so the agent can't be silently redirected. |
| **IDE code-completion / inline-suggestion models** (Copilot, Cursor Tab, JetBrains AI, …) running as you | A continuous read of your editor buffer + neighbouring tabs, streamed to (usually cloud) inference on every keystroke | A secret typed as a *literal into source* is ingested the instant it lands in the buffer — and with cloud inference it has **already left the machine before you finish the line** (the model suggesting the cred back, or offering to move it, is proof it read it; it may then propagate it into other files/commits). byn's mitigation is structural: secrets live in the vault and are referenced by *name* / injected at runtime via `byn exec`, so there is no literal in the buffer to slurp. byn can't intercept the IDE itself — keeping literals out of source is the control byn makes practical. |
| **A tampering attacker** with write access to `vault.db` or the audit log | Can modify on-disk state without the key | (a) Tampered ciphertext fails AEAD auth → vault refuses to open / decrypt. (b) Tampered audit log fails HMAC chain → `byn audit verify` flags first bad index → daemon error to user. **Honest limit:** the chain's HMAC seed is stored in the DB `meta` table, so an attacker who can read the file can also re-seal a rewritten chain — the HMAC defends against blind tampering, not against an adversary holding the whole file. Off-box anchoring of the chain head (journald / os_log / remote syslog) is the planned fix (ST-1). |
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
accepted limitations (notably env-var `/proc` readability — narrowed for
trusted-`.byn` pinned exec by opt-in `[security] privsep`, which drops the
child to the `_byn-exec` user; root/`CAP_SYS_PTRACE` remain the ceiling) are
the contract in [spec.md §9.4](spec.md).

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

## Known weaknesses & how to protect yourself

byn raises the bar against the *agent-era* leak — but it is a user-space
tool with real, named limits. This is the honest list of where it is weak,
what each weakness actually costs you, and the concrete thing **you** do
about it. Nothing here is hypothetical; each item is verified against the
code. Where there is no real in-product defense, that is stated plainly and
the workaround is an OS feature or an operating habit, not a byn promise.

| Weakness (plain language) | The realistic risk | What YOU do about it |
|---|---|---|
| **A stolen `vault.db` + `wrapped.key` is offline-crackable. The master password is the only barrier.** The vault is *portable by design* (no machine binding) — anyone who copies the files can guess passwords on their own hardware, forever, with no rate limit and no lockout (the failed-unlock backoff only protects the *live daemon*, not an offline copy). Argon2id (default 64 MiB / time=2) slows each guess but is not a high wall against GPUs/ASICs. | A weak or reused master password = full vault compromise once the file is copied. The Argon2 cost buys time, not immunity. | **Use a long, high-entropy passphrase** (a 5+ word diceware phrase, not a word + numbers). **Enable host full-disk encryption** (FileVault / LUKS) so the file can't be copied off a powered-down or stolen machine in the first place. A generated break-glass recovery key that would replace the memorable password as the portability root is **planned (PH-1) but not yet available** — do not rely on it today. |
| **Entry, project, and env *names*, kinds, timestamps, version counts, and file metadata are plaintext at rest.** Only secret *values* are encrypted. A copy of `vault.db` is a readable map of *what* you keep and *when* you touched it, even though every value stays sealed. (This is a deliberate owner trade-off: names are listable while locked, and investigators see what was accessed without unlocking.) | Names can themselves leak intent or secrets (e.g. `STRIPE_LIVE_KEY_acct_1234`, customer names, internal hostnames). | **Don't encode anything sensitive in names** — keep the secret in the value, give it a boring name. Rely on **host full-disk encryption** to protect the metadata of a file at rest. |
| **Same-UID processes (coding agents, IDE extensions, scripts) running as you can reach everything you can.** A process under your UID can: invoke `byn` itself; connect to the daemon socket directly (the peer-UID check passes — it's *you*); `ptrace` the unlocked daemon and read the vault key from memory; read injected env from a child it can see via `/proc/<pid>/environ` (mitigated for trusted-`.byn` pinned exec when `[security] privsep` is enabled — see below); and read a session file under the byn data dir (`sessions/`). This is **the core threat byn exists for, and the one it cannot fully close in user space.** | Any untrusted code you run as your primary user can, in principle, reach your unlocked secrets. byn makes this *smaller and louder* (every value access is audited, there's no plaintext `.env` to grab, sensitive ops demand fresh proof-of-presence) but does not make it *zero*. | **Run untrusted agents / tooling under a SEPARATE OS user, a sandbox, or a VM — never your primary UID.** This is the only complete fix. byn now ships **opt-in privilege separation** (`[security] privsep`, set up via `byn setup`): a trusted-`.byn` pinned `byn exec` runs its child as the `_byn-exec` service user, so a **non-root** same-(owner)-UID process can no longer read that child's injected env via `/proc/<pid>/environ` (root / `CAP_SYS_PTRACE` still can — the documented ceiling). It does **not** isolate the daemon itself or ad-hoc exec, and is off by default this release. Beyond that: **keep the vault locked when not in use** (`byn lock`), and **keep `idle_timeout` short** so a stolen session can't draw on an unlocked vault for long. |
| **A stolen session token from a *different* terminal is rejected — but the bound is TTY+UID, not per-process.** A CLI session token is bound to the controlling-TTY device number *and* UID (server-resolved at unlock), so copying a session file into a different terminal context fails. **Honest limit:** a malicious same-UID process can acquire your *current* controlling terminal via `TIOCSCTTY` and then present a request that looks correctly TTY-bound; and portal sessions are **UID-only** (no TTY bind at all). | The TTY bind stops casual token reuse across windows, not a determined same-UID attacker on your actual terminal. | Same fix as the row above: **isolate untrusted code to another UID.** Don't treat the session bind as a same-UID boundary — it isn't one. |
| **The audit log of a *stolen* file can be silently rewritten.** The HMAC chain's seed is stored as **plaintext** in the DB `meta` table (`audit_chain_seed`). Anyone holding the file can read the seed and re-seal a forged chain that passes `byn audit verify`. | A thief can erase their tracks in *their copy* of your log. The HMAC only proves integrity against an attacker who does **not** have the file. | Treat a copied vault file's audit trail as **unverifiable**. Off-box anchoring of the chain head (ST-1) is **planned, not shipped**. For now, the trustworthy audit signal is the one on the live, FDE-protected host — not a copy. |
| **Trusted `.byn` exec runs an approved command's *interior* unchecked.** byn pins and MAC-binds the command *list* (`[exec] actions`) — exact argv matches run free — but it does **not** inspect what those commands then *do*. A pinned `make build` runs whatever the current `Makefile` contains; a pinned script runs whatever the script now says. byn protects the *action list*, not the *action's behavior*. | A command you pinned can be repurposed by editing the file it executes (Makefile, script, etc.) without ever touching the `.byn`. | **Only pin actions whose scripts/targets you control** and review. **Review `byn trust diff` before re-trusting** a changed `.byn`. Don't pin interpreters or wildcards (`actions = "*"`) in environments where untrusted code can edit the executed files. |
| **The portal is loopback + an owner token, and any same-UID process can read that token.** `byn web` binds `127.0.0.1` (no network exposure) and gates `/api/*` on a 32-byte token in the byn data dir (`portal.token`, mode 0600). Loopback has no kernel UID gate, so the token is what stops *other* UIDs — but the file is readable by **your** UID, so any same-UID process can read it and drive the portal API. | Same same-UID ceiling as everywhere else: the token stops other users, not code running as you. | Same fix: **isolate untrusted code to another UID.** The token is doing its job (blocking other accounts on loopback); it is not, and cannot be, a same-UID boundary. |
| **Root, live memory, coercion, and a known password are genuine breaks — out of scope by design.** Root can read daemon memory/swap/files. A debugger attached to the unlocked daemon reads the key (`mlock` is best-effort, not a defense against root/ptrace). "Type your password or else" is not a crypto problem. An attacker who *knows* your password owns the vault. | These are not weaknesses byn pretends to cover — they are the perimeter. | **Don't run as root more than necessary**; **physically protect the machine**; **never share or reuse the master password**; **rotate immediately** on any suspicion it leaked. byn is the wrong tool to stop these — name them honestly and defend with the OS and operational discipline. |

**The one-line summary:** byn shrinks and audits the agent-era leak and keeps
plaintext off disk, but while an adversary runs as your UID — or holds a copy
of your file with a guessable password — the real boundaries are **a strong
passphrase, host full-disk encryption, and isolating untrusted code to a
different OS user.** Those three are not byn features; they are the controls
byn depends on.

---

## Known limitations (this release)

byn is a **development-time** secrets tool, not a production secrets manager.
With privilege separation enabled it runs your commands under a dedicated
service user and injects secrets there, so other processes running **as you**
cannot read those secrets from the environment, and every access is audited.
That is the win it is built for. These are the limits that come with it — read
them before you rely on byn for anything that matters.

- **Concurrent commands share one service user.** Two byn-run commands running
  at the same time are **not** isolated from each other — both children run as
  the single `_byn-exec` service user, so one could read the other's injected
  secrets from its environment. Don't run mutually-distrusting commands in
  parallel under byn.
- **No defense against root or a compromised byn service.** Anyone who can run
  code as root, as `_byn`, or as `_byn-exec` can read secrets. byn guards your
  dev workflow against ordinary same-user processes (agents, scripts, IDE
  extensions); it is **not** a hardware vault.
- **Autonomous (password-free) exec lowers the at-rest floor for the vars it
  covers.** Secrets that a trusted `.byn` allowlists for password-free exec are
  stored so the daemon can inject them **without** your master password; their
  at-rest protection is then the machine fingerprint + service-user isolation,
  not your password. This applies **only** to the vars your trusted `.byn` files
  allowlist (a `env = "*"` `.byn` opts its whole scope in); everything else
  stays password-protected at rest.
- **Physical and memory attacks are out of scope** — cold-boot, swap, and
  memory dumps can recover an unlocked key or injected secrets; byn does not
  defend against them.

The bottom line: byn is **not** a production secrets manager. It shrinks and
audits the agent-era leak on your own machine; it does not replace a hardware
HSM, a cloud secrets service, or OS/VM isolation.

---

## Best practices

A short, ordered checklist. Each line is the practice and why it matters.

1. **Use a long, high-entropy master passphrase** (5+ random words, not a
   tweaked dictionary word) — it is the *only* barrier on a stolen, portable
   vault file, and Argon2id alone won't save a weak one.
2. **Enable host full-disk encryption** (FileVault on macOS, LUKS on Linux) —
   it's what actually stops the vault file (and its plaintext names/metadata)
   from being copied off a lost or powered-down machine.
3. **Run AI agents and untrusted tooling under a separate OS user, sandbox, or
   VM — never your primary UID** — a same-UID process can ptrace the daemon,
   read injected env, and read the portal/session tokens; a different UID is
   the only real boundary today.
4. **Keep `idle_timeout` sane; don't set `"0s"` unless you accept the
   trade-off** — `[daemon] idle_timeout` (default 15m) auto-relocks an idle
   vault; `"0s"` disables relock entirely, so the key stays in memory until you
   stop the daemon, widening the window for a same-UID or memory attacker.
5. **Run `byn lock` (or `byn lock --session`) when you step away** — locking
   zeroes the in-memory key; `--session` drops just this terminal's access
   without disturbing other surfaces.
6. **Scope `[exec] env` to the minimum variables a command needs** — `byn exec`
   injects only the listed vars. Without privsep they are readable in the
   child's `/proc/<pid>/environ` by any same-UID process; with **`[security]
   privsep` enabled** (opt-in; `byn setup`) a pinned exec's child runs as
   `_byn-exec` so only root / `CAP_SYS_PTRACE` can read them. Either way, fewer
   vars = less to leak.
7. **Pin only actions whose scripts you control** (`[exec] actions`) — byn
   verifies the command *list*, not what the command then does, so a pinned
   target that runs editable code is only as safe as that code.
8. **Review `byn trust diff` before re-trusting a changed `.byn`** — a changed
   file is never silently re-trusted; the diff is your chance to catch a
   planted action or widened allowlist before you re-approve.
9. **Prefer passkey / Touch ID unlock where available** — it routes unlock
   approval out-of-band of the terminal an agent can drive (the PRF output
   never leaves the browser); the master password remains the durable root.
10. **Don't put secrets — or sensitive intent — in entry names** — names,
    scopes, and timestamps are plaintext at rest; keep the secret in the value.
11. **Rotate any credential the moment you suspect exposure** — an IDE
    completion that suggested a literal back to you, a leaked file copy, or a
    suspect agent run all mean the secret may already be off the machine;
    treat it as compromised and rotate.

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
    salt       = random 32 bytes (per-wrap),
    time       = 2,         // iterations  (DefaultArgon2Params)
    memory     = 64 MiB,
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

**Upper bounds** on Argon2 params: time ≤ 16, memory ≤ 1 GiB, threads ≤ 16
(lower bounds: time ≥ 1, memory ≥ 8 MiB, threads ≥ 1). Prevents DoS via a
malicious header and rejects an attacker swapping in trivial params on disk.

**Cost is modest — this matters for a stolen file.** The default profile is
tuned for ~1 s on a laptop, but 64 MiB / time=2 is *not* a high wall against a
funded offline attacker with GPUs/ASICs. It buys time against guessing, not
immunity. The real defense for a weak password is **a long, high-entropy
passphrase** — see "Known weaknesses" below.

**Why AAD = full header bytes:** binds every byte of the header
(version, salt, params, nonce) into the auth tag. Flip one bit of the
header → unwrap fails. Stops downgrade attacks (e.g., forcing weaker
Argon2 params) and salt-replacement attacks.

**Why XChaCha20 (24-byte nonce) and not AES-GCM (12 bytes):** random
nonces. With a 12-byte nonce, the birthday bound is ~2^48, which is
visible for long-lived keys. 24 bytes lifts it past anything we
realistically reach.

### 3. Row encryption

Every entry value is AEAD-sealed individually under a **per-row key**
derived from the vault key:

```
K_row      = HKDF-SHA256(
    secret = vault_key,
    info   = vault_id || 0x1F || kind || 0x1F || name,
)

ciphertext = XChaCha20-Poly1305-Seal(
    key   = K_row,
    nonce = random 24 bytes,
    plain = value bytes,
    aad   = vault_id || 0x1F || kind || 0x1F || name,
)
```

Stored format: `nonce || ciphertext_with_tag`.

**Why per-row keys (v2):** because each row is sealed under its own
`K_row = HKDF(vault_key, vaultID‖kind‖name)` (plus a fresh per-write nonce and
the AAD binding), the daemon can hand out **decryption capability for one
specific var** — by capturing just that var's `K_row` — without ever exposing
the vault key. This is what makes autonomous trusted-`.byn` exec possible: a
trusted `.byn`'s allowlisted vars have their per-row keys captured and wrapped
under a machine-fingerprint key (`K_cap`) in the trust record, so the daemon can
inject them with the vault **locked** and no password (see "Known limitations").
Everything not allowlisted stays sealed under a `K_row` only the unlocked vault
key can re-derive.

**Legacy v1 rows still decrypt.** Rows written before per-row keys were sealed
**directly** with the vault key (no HKDF step). Those `v1` rows are still read
correctly, and migrate to `v2` (HKDF per-row key) on the next write, rename, or
trust-capture of that entry — there is no bulk re-encryption.

**Why AAD includes vault_id, kind, name:** a row literally cut from
one vault and pasted into another (or one entry's bytes copied onto
another's row) fails to decrypt — and with per-row keys the `K_row` itself no
longer even matches. This catches both DB-level tampering and accidental
row-swap bugs.

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
attacker who *doesn't have the seed*. **Honest limit — the seed is
plaintext in the DB.** The seed lives in the `meta` table as plain hex
(`audit_chain_seed`); it is **not** encrypted under the vault key. Anyone
who can read `vault.db` can read the seed and silently re-seal a rewritten
chain. The HMAC therefore detects *blind* tampering by an adversary without
the file — it does **not** protect the audit trail of a copied file. Off-box
anchoring of the chain head (ST-1) is the planned fix and is not yet shipped;
until then, treat a stolen file's audit log as unverifiable.

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
- macOS: `LOCAL_PEERCRED` (Xucred) returns the peer UID; `LOCAL_PEERPID`
  returns the PID (best-effort).

If peer UID ≠ daemon owner UID, the connection is closed
immediately — before reading the request.

**Why:** stops another local user from connecting if file modes were
accidentally loosened (e.g., a chmod typo).

### Privilege separation: the three-UID model (opt-in, NU-5/6)

By default the byn daemon and any `byn exec` child run as **your own UID** — the
same identity as the AI agents, IDE extensions, and scripts you run. That is the
root of the dominant residual threat: a process running as you can `ptrace` the
unlocked daemon and lift the vault key from memory, or read an exec child's
injected environment via `/proc/<pid>/environ` (Linux) / `KERN_PROCARGS2`
(macOS). No user-space gate inside byn closes that, because the attacker *is* you
as far as the kernel is concerned.

Privilege separation splits those roles onto **three distinct OS identities** so
the kernel — not byn — enforces the boundary:

| Identity | Runs | Holds |
|---|---|---|
| **owner** (your UID, e.g. 501) | the CLI, the browser portal, the TUI, your agents | nothing privileged; talks to the daemon over the peercred-gated socket |
| **`_byn`** (service account) | the daemon — vault key in memory, portal server, audit writer | the vault key while unlocked |
| **`_byn-exec`** (service account) | `byn exec` children of a trusted, pinned `.byn` action | only the injected env vars, for the child's lifetime |

The invariant is **`_byn-exec` ≠ `_byn` ≠ owner**. The exec child gets its *own*
service UID, separate from the daemon's: if it shared the daemon's UID it could
ptrace the daemon and lift the key, which would make privsep self-defeating
(exec runs arbitrary project code).

**What it defends.** Once the daemon is `_byn` and an exec child is `_byn-exec`,
a process at *your* UID is a different UID from both of them. On Linux the
`ptrace(2)` access-mode check denies a cross-UID `ptrace` / `/proc/<pid>/mem` /
`/proc/<pid>/environ` read at credential comparison — it requires root or
`CAP_SYS_PTRACE`. On macOS the XNU kernel returns `EINVAL` on a cross-UID
args/env read by a non-root caller, and `task_for_pid` across a UID boundary
requires root. So the env-sniff and the key-from-memory reads that *any*
same-UID process can do today both become **root-only**. On Linux byn also calls
`prctl(PR_SET_DUMPABLE, 0)` in the daemon and the exec child after the credential
switch — this reparents their `/proc/<pid>/*` to `root:root` and disables core
dumps, closing the same-UID residual (a leftover process that briefly shares the
service UID still can't read them).

**The honest ceiling — stated loudly.** Privilege separation raises the bar from
"any code running as you" to "**root**." It does **not** defend against an
attacker who already has **root**, `CAP_SYS_PTRACE`, or a root `task_for_pid`:
root reads any process's memory and environ and can assume any UID, on both
OSes, by the *same* kernel checks that give us the win against non-root. This is
the documented limit. Privsep is not a root defense — closing the root gap needs
hardware-rooted isolation or off-box execution, which is out of scope. Root
refusal (the daemon declines to start as uid 0 unless you pass `--allow-root`) is
posture hygiene to keep the `_byn` separation coherent; it is **not** a defense
against an attacker who *has* root.

**Opt-in this release; the holes remain when it is off.** Privsep is **off by
default** in this release and enabled per-machine with `[security] privsep` in
the config plus a one-time `byn setup` (which needs sudo once, to create the
`_byn`/`_byn-exec` service accounts and install the system service). **When
privsep is off, both holes above are fully open** — the daemon and exec children
run as your UID, so a same-UID process *can* ptrace the daemon and read exec
env. We do not pretend otherwise. Privsep also only covers a **trusted, pinned**
`byn exec` (a `.byn` `[exec] action`); an **ad-hoc** `byn exec` (no `.byn`) still
runs its child as the owner even with privsep on, and a same-UID process can read
that child's environ.

**Fail-safe, never silent downgrade.** With privsep opted-in but the machine not
yet provisioned (`byn setup` not run, or the sudo declined), byn **errors loudly
and refuses to fall back** to a ptrace-able owner-UID daemon — falling back would
silently drop the protection you turned on. The only non-privsep paths are
explicit and documented: an unprovisioned install, or the per-exec
`--no-privsep` escape. `--no-privsep` (a `byn exec` flag) forces the **legacy
in-process exec path** for that one invocation even when privsep is enabled — the
child is run by the calling user via `execve(2)` instead of being spawned under
`_byn-exec`. It exists for cases where the service-user path can't be used; it is
**lower-assurance** — that child runs at the owner UID, so a same-UID process can
read its `/proc/<pid>/environ` (the §"Known weaknesses" env-read hole applies).
Use it only when you accept that trade-off.

**Why `NoNewPrivileges=no` on the systemd unit (intentional, not an oversight).**
The Linux unit deliberately sets `NoNewPrivileges=no`. The `_byn` daemon spawns
exec children as `_byn-exec` through a tiny, file-capability spawn helper that
holds `cap_setuid`/`cap_setgid` (file caps, root-owned, hardcoded target UID, no
flags, no env). If the unit set `NoNewPrivileges=yes`, the kernel would **strip
those file caps** at exec time, and the helper could no longer drop the child to
`_byn-exec` — breaking the whole privsep chain. This is a conscious trade-off: we
keep `NoNewPrivileges` off so the *scoped* helper can do its one privileged
operation, rather than parking ambient `CAP_SETUID` on the long-lived,
IPC-exposed daemon for its entire life (which would be a far worse blast radius
on a daemon hijack). The helper takes no untrusted input and lives milliseconds.
The unit is otherwise hardened: `ProtectSystem=strict`, `ProtectProc=invisible`,
`ProcSubset=pid`, `RestrictAddressFamilies=AF_UNIX`,
`SystemCallFilter=@system-service`, `MemoryDenyWriteExecute=yes`.

**macOS: hardened runtime needs Developer ID signing.** The strongest macOS
posture for the held key is shipping the daemon with the **hardened runtime** and
*without* the `com.apple.security.get-task-allow` entitlement — then even root
cannot `task_for_pid` the daemon. **This is only real on signed builds.** It
requires a Developer ID signature applied at release; **unsigned local/dev builds
do not get the hardened runtime** and therefore do not get that property. The
GoReleaser config documents this; do not assume a `go build` of byn has it.

### Portal loopback + owner-token gate

The embedded browser portal (`byn web`) binds `127.0.0.1:<port>`. Loopback
prevents network access but does **not** prevent other local user accounts from
reaching the port over TCP — loopback has no kernel UID gate.

byn closes this gap with an **owner-token gate** using a two-token design that
keeps the long-lived token out of `ps` output and URLs:

**Persistent portal token** (`portal.token` in the byn data dir):
- A 32-byte random hex file created at mode 0600 on daemon start (persisted
  across restarts). Only the owner UID can read it.
- Every `/api/*` request must carry `X-Byn-Portal-Token: <token>` (constant-
  time compare). Missing or wrong → 401 `portal_token_required`.
- This token never appears in argv or browser URLs.

**One-time bootstrap token** (in-memory, 60 s TTL):
- `byn web` calls the UID-gated Unix socket (`web.bootstrap` op) to mint a
  single-use bootstrap token and opens `?auth=<bootstrap-token>`.
- The SPA calls `POST /api/session/bootstrap` with the bootstrap token, receives
  the persistent portal token, stores it in `localStorage`, and strips `?auth=`
  via `replaceState`. A `ps`-captured bootstrap token is single-use and expires
  in 60 s.
- `POST /api/session/bootstrap` is ungated by the owner-token (the caller does
  not have it yet) but is `sameOrigin`-gated to prevent cross-site replay.

Static assets and the SPA shell (`/`, `/static/`) are ungated — the HTML is
harmless without a valid token.

A **CSRF defense** (`sameOrigin` Origin check) is applied on top of the token
gate to all mutating routes. Both layers are necessary and complementary:

| Layer | Attacker stopped |
|---|---|
| `requireToken` | Other-UID process that can reach loopback TCP |
| `sameOrigin` | Browser-based CSRF from a different origin |

The daemon's own code **does not call the HTTP API** — it uses in-process
`Dispatch` directly, so the token gate never blocks daemon-internal calls.

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

### Server-side exec allowlist

`byn exec` is authorized in a single IPC round-trip: the daemon reads,
trust-verifies, and parses the `.byn` itself, then returns **only** the
entries listed in `[exec] env`. A compromised client process cannot
widen the allowlist by sending a different request — the daemon owns the
entire path from trust check to env assembly. Denial messages
(untrusted / changed / tampered / stale) originate in the daemon.
Every exec attempt — including locked-vault and trust failures — is
written to the audit log with the full command line.

`byn exec` does **not** draw on the unlock / session state the way
`get`/`put`/`update` do. A trusted `.byn` with a matching `[exec] actions`
entry runs **autonomously** — no unlock, no password, **even while the vault
is locked** — decrypting only its allowlisted vars via a capability sealed in
the trust record (machine-fingerprint-wrapped, no in-memory vault key). An
**unpinned** command on a trusted `.byn` requires a fresh master password per
run (still no unlock). Only **ad-hoc exec** (no `.byn`, which injects the whole
scope via the in-memory vault key) requires the vault unlocked. An active
unlock session never authorizes exec — so `byn unlock` governs
`get`/`put`/`update`, not `exec`.

### [exec] actions: which commands may run free

The env allowlist (`[exec] env`) controls *which variables* are injected.
The actions pinlist (`[exec] actions`) controls *which commands* may run
without fresh per-call authorization. The two are independent — a command
can be pinned without any env vars flowing, or env vars can flow into a
command that requires auth each time.

**Three-state semantics (NU-2):**

| State | Behavior |
|---|---|
| `actions` absent or empty | **Secure default.** No command runs free — every `byn exec` requires authorization (password or presence token). Existing `.byn` files without `[exec] actions` behave this way after re-trust. |
| `actions = "*"` or `["*"]` | **Wildcard.** Any command runs without re-authorization. CLI prints a loud warning on every exec. Use only in fully-trusted environments. |
| `actions = ["cmd arg", ...]` | **Explicit list.** Only exact argv matches (joined with spaces) run free; all others require authorization. |

**[auth] exec policy** (optional, in the `.byn` `[auth]` table):
- `"always"` — fresh auth for every exec, even pinned/wildcard commands. Strongest.
- `"none"` — no auth for any command. Equivalent to `actions = "*"` but bypasses
  the wildcard warning at exec time. The warning is shown at `byn trust` time (Task 3).
- `"trusted"` — default; let the actions list decide.

**Tamper-evidence:** actions and auth policy are MAC-bound into the trust
record at grant time. The daemon reads policy from the record, not from the
live file, so editing the `.byn` after trust is granted cannot change the
effective actions policy without re-trusting (which requires the password).

**Independence from the session gate:** the actions gate applies regardless
of whether a session is active. The session gate governs value-touching
operations that have no `.byn` contract (ad-hoc exec, `get`, `put`,
`delete`, …). A `.byn`'s `[exec] actions` list is the contract for
trusted-`.byn` exec. Having an active session does NOT add extra prompts
to a trusted-`.byn` exec that has a pinned command.

**`[auth] exec` scope:** the `exec` key in `[auth]` applies only to
trusted-`.byn` exec (Path present). Ad-hoc exec (no `.byn`) is governed solely
by the NU-3 session gate — `.byn` policy is never consulted for ad-hoc
exec, because ad-hoc exec injects the whole scope with no env allowlist, and a
`.byn`'s policy contract is tied to that file's own env allowlist.

**Migration:** existing `.byn` files have no `[exec] actions` after re-trust
— every exec will prompt for authorization until you add `actions`. This is
intentional: the secure default is that no command runs free.

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

### NU-3 authorization gate

The NU-3 session matrix requires either a live session or fresh credentials
for every sensitive call, **even while the vault is already unlocked** by
another terminal. This is the default; it is not opt-in.

**Gated operations:** `get`, overwrite-`put`, `delete`, `rename`,
`env clear`, `env delete`, `project delete`, `vault delete`,
`vault rename`, and **ad-hoc `exec`** (no `.byn`). Insert (new name),
`list`, and trusted-`.byn` `exec` stay free — the `.byn` is the
authorization for exec. Ad-hoc exec (no `.byn`) is gated because it
hands out the entire scope; running from a directory with a trusted
`.byn` is the zero-prompt alternative.

**CLI flow:** when the daemon returns `auth_required`, the CLI prompts
once ("Authorization required.") and retries with the supplied password.
`--password-stdin` is supported for non-interactive use. In `--json`
(agent) mode no prompt is shown; the call fails actionably so the caller
can supply `--password-stdin` and retry. A wrong password is rejected
and rate-limited exactly like `byn unlock`.

**`put --password-stdin` contract:** with `--password-stdin`, the
**first line** of stdin is always the master password and the
**remainder** (after the first newline) is the secret value. The first
line is consumed unconditionally — even when the daemon does not ask
for authorization (e.g., for a new key being inserted for the first
time). This makes the contract byte-stable:

```sh
{ echo "$BYN_PW"; printf 'new-val'; } | byn put key --password-stdin
```

For `get` / `rename` / `delete` with `--password-stdin`, the entire
stdin (no newline split) is read as the password.

**Locked vault vs. auth_required:** the behaviors are different.

| Scenario | Recovery |
|---|---|
| `get` / `put` / `rename` on a **locked vault** | Hard fail with "byn unlock" hint — a password alone cannot decrypt a locked vault |
| `get` / `put` / `rename` with no active session (vault is unlocked) | Prompt / `--password-stdin` once; daemon verifies without changing lock state |
| `delete`-family on a **locked vault** | Password alone authorizes — vault stays locked, no values exposed |
| `delete`-family with no active session (vault is unlocked) | Same password flow as above |

**Portal step-up:** when no active session is present, the web portal shows
an "Authorize" modal on any write/delete/reveal. Passkey (Touch ID /
iCloud Keychain) is tried first; password is the fallback. On success,
the daemon issues a **single-use presence token** (32 random bytes,
consumed on first use, never stored beyond the one request). A wrong
password or expired/unknown token is rejected and does not change the
vault's lock state.

**`export` under a session (NU-3):** with an active session in the current
terminal, `byn export` issues one `get` per entry and every get is authorized
by the session token — zero password prompts. Without a session, the first
`get` returns `auth_required` and the CLI prompts once interactively (or reads
from `--password-stdin`) and reuses the same password for all subsequent gets.
Each per-password get re-verifies via Argon2id, so large exports without a
session are slow. Running `byn unlock` first (or using `--password-stdin` on
`byn export`) avoids this cost.

**Honest ceiling:** the session gate raises the cost for a same-UID
adversary that does not control the terminal that unlocked — it can no longer
draw on an ambient unlocked session silently. It does **not** stop a process
running as you from calling the daemon socket directly (same-UID peer-credential
check is unchanged), ptracing the daemon while unlocked, or acquiring the TTY
via `TIOCSCTTY` (see NU-3 session model above). Privilege separation (NU-5/6)
is the path to a stronger UID boundary.

### `.byn` `[auth]` per-scope policy

The `[auth]` table in a `.byn` file can override the NU-3 session gate
**per operation, per scope**. This lets a team commit a policy alongside
the project config and have it take effect automatically for anyone who
trusts the file.

**Keys:** `get`, `update` (overwrite-put, rename, vault-rename),
`delete` (delete, env.clear, env.delete, project.delete, vault.delete),
`exec`. Values: `always`, `none`. (The `exec` key is enforced
separately via the `[exec]` actions gate; see the actions section.)

**Values and their effect on the session gate:**

| Value | Effect |
|---|---|
| `always` | Fresh auth unconditionally (even with an active session). Tightens. |
| `none` | Gate skipped entirely for the matched scope (no auth needed). Relaxes. |
| absent | Session gate decides (default NU-3 semantics). |

**Policy lookup rules:**

1. **Vault must be unlocked.** The policy is bound to the trust record
   by VKMAC (vault-key-derived HMAC). Without the vault key the MAC
   cannot be verified, so policy is ignored and flag semantics apply.
   This is intentional — a policy that can't be verified is not
   trustworthy.

2. **Only v2 records with non-empty `[auth]`.** v1 records (no mtime
   or snapshot, pre-NU-2 format) are never policy sources.

3. **VKMAC must verify.** A record whose Auth field was edited after
   grant (breaking the VKMAC) is silently ignored. Re-trust to mint a
   fresh MAC.

4. **Scope matching with specificity.** A record's `[scope]` is
   compared to the request's (vault, project, env), with `""`
   normalizing to `"default"` on both sides. Three specificity levels:

   | Level | Match |
   |---|---|
   | 3 (most) | vault + project + env all present and matching |
   | 2 | vault + project match; env unset on the record |
   | 1 (least) | vault only; project and env unset on the record |

   The most specific matching record wins per key. A vault-only record
   (`[scope]` with no project/env) applies to ALL scopes within that
   vault unless overridden by a more-specific record.

5. **Tie at the same specificity → strictest value wins.** If two
   records match at the same level and declare the same key, `"always"`
   beats `"none"` beats absent. This ensures that layering a relaxing
   policy on top of a tightening one never silently widens access.

6. **No caching.** The trust store is read on every call. This keeps
   a freshly-granted `.byn` effective immediately without a daemon
   restart, at the cost of one small JSON read per gated op.

**Structural-ops scope note:** vault-level operations (`vault.delete`,
`vault.rename`) pass `Scope{}` (no project/env) to the policy gate. A
vault-only record (project and env both unset in `[scope]`) matches `Scope{}`
and therefore also gates vault-level ops. A record broadly scoped to an entire
vault is deliberate: the operator knows they are granting policy for the whole
vault.

**Security note:** like all `.byn` trust, the policy is MAC-bound at
grant time. A same-UID process can write `trusted_byn.json` directly
(mode 0600 keeps others out but not you), which is the same user-space
ceiling as the trust store itself. Re-signing with a daemon-resident
key is deferred hardening (see table above); the VKMAC layer is the
current protection against offline forgery.

### Agent mode (`--json`)

When `--json` appears anywhere before `--` in argv, byn refuses
to interactively prompt for anything. Specifically:

- Untrusted `.byn` file → hard error (not a y/N prompt).
- Tampered `.byn` file → hard error.
- `auth_required` (no active session) → hard fail; supply
  `--password-stdin` instead.

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
myapp-agent/staging.` Never `Stored "DB_URL=…" in …`. Set
`BYN_HINTS=0` to suppress even those.

---

## Audit & forensics

- Audit chain is HMAC-signed → tampering detectable but not preventable.
  **Caveat:** the HMAC seed lives in the DB itself, so this detects
  tampering by adversaries who *don't* hold the file; a thief with the
  whole file can re-seal a rewritten chain. Off-box chain-head anchoring
  (ST-1) is the planned fix; until it ships, treat a stolen file's audit
  trail as unverifiable.
- **At-rest metadata is deliberately visible (owner decision, 2026-06-12).**
  Entry/project/env names, kinds, timestamps, version counts, and file
  metadata are readable from `vault.db` without any key — only *values*
  are encrypted. This is the price of two product promises: names are
  listable while the vault is locked (the agent workflow), and
  investigators see *what* was accessed without unlocking. Know that a
  copy of your vault file is a map of what you keep, even if every value
  stays sealed. If that exposure matters in your environment, full-disk
  encryption of the host is the right control today.
- Caller UID + PID captured per event when the OS surfaces them.
  Helps trace which agent or shim made the call.
- `byn doctor` runs verify on every vault's chain at any time.

---

## NU-3 session model and no-global-unlock

**This is a behaviour flip. Read before upgrading.**

### What changed

NU-3 replaced the old ambient-unlock model with **per-terminal, per-surface
sessions**. Under NU-2 and earlier, running `byn unlock` in any terminal
effectively opened the vault for every process with your UID — a coding agent,
a background script, or a second shell could all `byn get` freely once any one
terminal had unlocked. Under NU-3, **an unlocked vault does not grant other
same-UID callers anything**. Each terminal, portal tab, or TUI session must
authenticate independently.

#### Session binding

A session token is minted by the daemon when `byn unlock` (or `byn web`
unlock, or TUI unlock) succeeds. The daemon binds the token to:

- **vault name** — the token is only valid for the vault it was minted for.
- **effective UID** — always enforced; cross-UID use is impossible.
- **controlling-TTY device number** — for CLI sessions, the daemon resolves the
  socket peer's controlling terminal at mint time (Darwin: `Eproc.Tdev` via
  `kern.proc.pid` sysctl; Linux: `tty_nr` from `/proc/<pid>/stat`). Commands
  from the same terminal window (and child processes that inherit it) reuse the
  session; a request from a different terminal is treated as unauthenticated.

Portal sessions use **uid-only binding** (ttyDev = 0) because there is no
socket peer — the browser portal authenticates through the owner-token gate,
not through a TTY. Daemon-process reloads preserve portal sessions; `byn lock`
clears them.

#### Token storage

The CLI writes the token to `sessions/<hash>` (mode 0600) in the byn data dir. The file
name is a truncated SHA-256 of `"ttyDev\x00vault"`, so each
terminal-plus-vault pair has one file. Subsequent commands in the same terminal
automatically load and forward the token without re-prompting.

#### Honest limits

- **Same-UID TIOCSCTTY residual:** a malicious same-UID process can acquire
  the current controlling terminal via `TIOCSCTTY` and then construct a request
  that looks TTY-bound. This is an accepted gap at user-space; privilege
  separation (agents on their own UID) is the closure.
- **Root ceiling:** unchanged. Root can read daemon memory, socket, and session
  files.
- **TTYDev-0 degradation:** when a socket caller has no controlling terminal
  (piped script, CI), the session falls back to uid-only binding. A warning is
  logged. That session accepts any same-UID caller on the socket, which is
  tolerated because the socket is mode 0600 and already UID-gated.

---

### NU-3 migration guide

#### What breaks

| Scenario | Old behaviour | New behaviour |
|---|---|---|
| `byn unlock` in terminal A, then `byn get KEY` in terminal B | **Worked.** Vault was unlocked for all callers. | **Fails with `auth_required`.** Terminal B has no session. |
| Script that calls `byn get KEY` without unlocking first | Worked if any terminal had unlocked | Fails with `auth_required`. Script must supply credentials. |
| `[security] per_action_auth = true` in config | Required per-call password | Config key is **removed**. Writing it to `~/.byn/config` causes the daemon to reject the config with an unknown-key error. Remove the key. |
| `byn export` without an active session | Would prompt per-entry | With an active session, zero prompts. Without a session, `auth_required`. Use `--password-stdin` or unlock first. |

#### What to do

**Interactive use (daily driver):**

```sh
# Unlock once per terminal window. This authorizes get/put/update/delete for
# THIS terminal's session only (not other terminals, the portal, or scripts).
# It does NOT affect exec — exec is governed by the trusted .byn + per-action
# auth, independent of unlock/session state.
byn unlock

# get/put/update in this terminal now carry the session token — no re-auth.
byn get DB_URL

# exec is separate from unlock: a trusted-.byn PINNED command runs free
# regardless of lock state; an unpinned command (or ad-hoc exec with no .byn)
# prompts for the master password. The `byn unlock` above neither helps nor is
# required for it.
byn exec -- make migrate      # runs free iff 'make migrate' is pinned in the .byn

# When done, revoke this terminal's session without locking the vault
# for other callers (e.g. the portal).
byn lock --session
```

**Non-interactive / CI / scripts:**

```sh
# Option 1: password-stdin on every call.
echo "$BYN_PW" | byn get DB_URL --password-stdin

# Option 2: unlock once (prints session file), then work.
echo "$BYN_PW" | byn unlock --password-stdin
byn get DB_URL       # session file present; no re-auth needed

# Option 3: [auth] none in the .byn (disables the auth gate for
#             that scope/operation — use sparingly).
```

**Agents (`--json` / byn exec inside a trusted `.byn`):**

- Trusted `.byn` exec with a pinned `[exec] actions` entry **runs free** —
  no session or credentials required. This is unchanged.
- Ad-hoc exec (no `.byn`) **requires auth**. Supply `--password-stdin` or
  run from inside a trusted `.byn` scope.
- `list` and new-name `put` (insert) are **always free** — no session needed.

**Config cleanup:** if your `~/.byn/config` contains a `[security]`
section with `per_action_auth`, remove that key. The strict TOML parser
will reject any config containing `per_action_auth` as an unknown key,
preventing the daemon from loading.

---

## NU-2 migration guide

NU-2 (released after v0.1.0) hardened the trust store with per-record
snapshots, mtime tracking, vault-key MACs, and an `[exec] actions` command
allowlist. Existing trust records created before NU-2 are classified as
**stale** and blocked from exec until re-trusted.

### What you will see

```
Error: /path/to/project/.byn predates tamper-protection — run `byn trust /path/to/project/.byn`
```

This is expected for every `.byn` you trusted before NU-2. Re-trusting
upgrades the record to v2 (snapshot + mtime + MACs).

### One-time re-trust

```sh
# Single file:
byn trust ./.byn

# Many files at once (one password prompt per vault):
byn trust --paths "a/.byn,b/.byn,c/.byn"

# Whole monorepo tree:
byn trust --recursive ~/projects
```

### Re-trusted .byns without [exec] actions

A `.byn` re-trusted without an `[exec] actions` key will prompt for
authorization on **every** `byn exec` invocation — this is intentional.
`[exec] actions` is the mechanism that pre-authorizes a specific command
list so those commands run password-free; without it, every exec requires
explicit approval. To avoid repeated prompts, add the commands you want to
run freely:

```toml
[exec]
actions = ["/usr/bin/env", "/usr/local/bin/make"]
```

### byn trust diff workflow

When exec fails with `CHANGED` or `STALE`, inspect what changed before
re-trusting:

```sh
byn exec -- make build      # fails: .byn has CHANGED
byn trust diff ./.byn       # exits 1; prints unified diff to stdout
                             # (mtime-only: "content identical; modification time changed")
byn trust ./.byn            # re-approve (prompts for password)
byn exec -- make build      # succeeds
```

`byn trust diff` exits **0** when content and mtime are both unchanged
(file is still trusted, nothing to do), **1** when either differs
(re-trust required), **2** when the daemon is not running, or **3** when
the daemon returns an error (path not trusted, file exceeds 64KB, etc.).

### Pluggable auth-provider seam

The auth-provider registry introduced in NU-2 exposes an interface
(`auth.Provider`) so additional authentication methods (phone approval, SSO,
hardware token) can register without forking byn. byn ships `password` and
`passkey` providers; additional providers register at startup via the registry.
This keeps the unlock surface extensible for self-hosted custom integrations.

---

## Deferred hardening

Tracked items, designed but not shipped. Pull forward as the
deployment surface grows.

| Item | Why deferred | When to revisit |
|---|---|---|
| Trust-file HMAC | Realistic attacker who can write `~` already owns more dangerous surfaces | After Slice 7; ~80 LoC; see internal design notes |
| Auth-state signing | Same threat model as trust-file | Together with the trust-file hardening |
| Constant-time rate-limit responses | Timing oracle on failed-unlock counts is low value (attacker already has the encrypted DB if they can time you) | When byn ships to multi-user servers |
| macOS SE wrapping | Needs dev signing + entitlements + a Mac CI runner | Slice 1.3 (was on the PLAN; deferred for delivery) |
| Linux TPM2 wrapping | Same as SE, plus tpm2-tss is a heavy dep for casual users | Slice 1.3 |
| `--quiet` flag | `BYN_HINTS=0` + shell redirection works | When users ask for it |
| Constant-time `wrong_password` vs vault-not-found | Same response today (existence oracle defense) | If we ever change that |
| **OS deny-read layer** (Seatbelt/Landlock) paired with the shim | A PATH-shim alone is bypassable (abs path, `PATH` rewrite, direct file read); containment needs a kernel deny-read on the cred files. Out of scope pre-public. | Phase 3, when shims land; see internal design notes |
| **Privilege separation: default-on** (NU-5/6 shipped opt-in) | The three-UID model (daemon `_byn`, exec child `_byn-exec`, owner) ships **opt-in** this release (`[security] privsep` + `byn setup`) — see ["the three-UID model"](#privilege-separation-the-three-uid-model-opt-in-nu-56). When **off**, a same-UID process can still ptrace the daemon and read exec env. Making it default-on waits until the migration is proven in the field. | Next release, once `byn migrate`/`byn setup` are proven; the root ceiling is permanent |
| **Fingerprinted exec allowlist** | Only pre-authorized commands get exec rights — strong for sealed tools, defeated for agent-authored interpreters | Phase 3, with shims |
| **Ephemeral scoped credential broker** | Vend short-lived STS tokens via AWS `credential_process` so the durable key never leaves the daemon (Case B cloud creds) | Post-launch; larger scope (cloud integration) |

---

## Related

- [Architecture](architecture.md) — IPC, scope, schema, daemon process model.
- [`.byn` + discovery](byn-file-format.md) — TOFU details.
- [CLI reference](cli-reference.md) — every flag and env var.
