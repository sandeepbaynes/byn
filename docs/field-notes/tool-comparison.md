# byn vs the other tools, honestly

*Field note · coverage: v0.4.0 · updated with each release*

A strengths-**and**-weaknesses comparison of the tools developers
actually use to handle secrets — including byn's own weaknesses, listed
just as bluntly. Two ground rules:

1. **These are mostly good tools.** Doppler, Infisical, Vault, 1Password,
   aws-vault, direnv, and mise are well-built for what they target. The
   honest claim is not "byn is better" — it is that they target a
   *different problem* (supplying production/pipeline environments) and
   byn targets the one they leave open (the dev machine itself, operated
   by agents).
2. **byn is young.** It is pre-1.0, single-owner-focused, and has real,
   named gaps. They're in this page too.

The one-line orientation: **if your problem is getting secrets into
prod/CI, pick a platform below — they're excellent at it. If your
problem is a dev machine full of agents and plaintext credentials, that
is byn's problem statement, and you can run byn *alongside* any of
them.**

---

## Plain `.env` files / dotfiles (the incumbent)

- **Strengths:** zero setup, universal tool support, works offline,
  nothing to learn. This is why it's the default.
- **Weaknesses:** plaintext readable by every process under your UID
  (the entire agent-era leak surface); no audit of who read it; slips
  into commits, backups, and snapshots; long-lived broad credentials by
  habit. Every incident on the
  [real-world incidents](real-world-incidents.md) page begins here.

---

## direnv

- **Strengths:** beloved, battle-tested developer experience —
  per-directory env loading, tiny, scriptable, everywhere. Composes
  with other tools (including byn).
- **Weaknesses for this threat:** it is an env *loader*, not a secret
  *manager* — `.envrc` typically holds or sources plaintext values on
  disk; no encryption, no access control, no audit. Pointing direnv at
  a secrets backend helps storage but still materializes values into
  the shell's ambient environment, where every child process inherits
  them.

---

## mise-en-place (mise)

- **Strengths:** excellent modern toolchain + task + env manager; fast;
  has grown secrets-aware features (e.g. sops/age-encrypted env files),
  which is genuinely better than raw dotfiles.
- **Weaknesses for this threat:** env files are plaintext by default
  and decrypted values land in the ambient environment of whatever runs
  in the directory — agents included. No per-access gating or audit on
  the dev box; security is an add-on, not the design center.

---

## Doppler

- **Strengths:** polished cloud secrets platform — environments,
  branch configs, sync integrations to every CI/cloud, rotation,
  team/org management, **server-side** access logs. For pipeline and
  runtime secrets delivery, genuinely strong.
- **Weaknesses for this threat:** the design center is the cloud
  workspace, not the dev box. The local CLI is an access path: once
  authenticated, any same-UID process can run `doppler run` and receive
  the values; the CLI token is cached locally; there is no local
  per-access audit, no per-command authorization, and no offline
  operation. Your secrets also live with a third party — fine for many
  orgs, a real dependency nonetheless.

---

## Infisical

- **Strengths:** open-source and self-hostable (a real differentiator
  vs Doppler), broad integrations, secret scanning, growing
  PKI/SSH/dynamic-secrets features, machine identities for CI.
- **Weaknesses for this threat:** same shape as Doppler from the dev
  box's point of view — a platform→pipeline tool whose local CLI
  session is ambient to your UID; machine-identity/auth tokens persist
  locally; per-access visibility lives server-side, not on the machine
  where the agent runs; no per-command gating.

---

## HashiCorp Vault

- **Strengths:** the production gold standard — dynamic secrets,
  leases and revocation, fine-grained policies, audit devices,
  ephemeral DB/cloud credentials. For infrastructure runtime secrets,
  nothing here competes with it.
- **Weaknesses for this threat:** it was never meant for the laptop.
  Heavy to operate; and the standard dev login flow drops a **plaintext
  token at `~/.vault-token`** — readable by any same-UID process, which
  can then fetch whatever your policies allow. Server-side audit won't
  distinguish you from the agent using your token. (Also BUSL-licensed
  since 2023, for those comparing licenses.)

---

## 1Password CLI (`op run`)

- **Strengths:** superb UX; biometric unlock via the desktop app with
  genuinely good per-app authorization prompts; secret references
  (`op://…`) keep literals out of `.env` templates; mature, audited
  vendor.
- **Weaknesses for this threat:** an authorized CLI session is usable
  by the processes it spawns and there is no per-*command* allowlist —
  `op run -- <anything>` injects into whatever is named. No local
  per-access audit trail you can query on the box. Closed source,
  subscription, cloud-account dependency.

---

## aws-vault

- **Strengths:** free, open source, stores AWS keys in the OS keychain,
  vends **short-lived STS session credentials** — a genuinely strong
  property this page happily credits (it limits what a thief gets).
- **Weaknesses for this threat:** AWS-only; authorizes credential
  *retrieval*, not commands — any process that can run `aws-vault exec`
  gets a working environment; no audit log; keychain access is ambient
  once the login session is unlocked; injected session creds are still
  readable in the child's environ.

---

## byn

- **Strengths (the combination the others lack):** local-first, no
  account, works offline; values AEAD-encrypted at rest with **no
  plaintext files**; **per-terminal sessions** (your unlock grants an
  agent's shell nothing); **pinned per-command allowlist** (`[exec]
  actions`) so only approved commands run without fresh auth;
  agent-mode (`--json`) hard-fails instead of showing prompts an agent
  could game; **local, HMAC-chained per-access audit trail**;
  committable names-only `.byn` manifest with tamper-evident trust;
  free and source-available.
- **Weaknesses (just as honestly):**
  - **Young.** Pre-1.0, small community, no independent third-party
    security audit yet. The [security model](../security.md) is
    documented honestly, but maturity takes time.
  - **The same-UID ceiling is real in v0.4.0 by default.** With privilege
    separation off (the default), a code-executing process as your UID can
    still ptrace the *unlocked* daemon or read an injected child's environ.
    Privilege separation (daemon and exec children on their own service UIDs)
    ships **opt-in** in v0.4.0 — enable it with `[security] privsep` +
    `sudo byn setup`; it raises the bar to root but not past it. With it off,
    OS-level isolation of untrusted code is the recommended companion control.
  - **The master passphrase is the at-rest floor.** The vault file is
    portable by design (no machine binding), so a stolen copy is
    offline-crackable against a weak passphrase. A machine-bound wrap
    with a break-glass recovery key is planned.
  - **Entry names are plaintext at rest** — deliberate (listing while
    locked is a feature), but a copied vault file is a map of *what*
    you keep.
  - **A stolen file's audit trail is re-sealable** until off-box
    chain anchoring ships (planned).
  - **Coverage gaps today:** SSH keys and tool-specific shims
    (`aws`, `gcloud`, …) are roadmap, not shipped; no cloud sync yet
    (roadmap) and no multi-human team sharing — byn is single-owner by
    design (one human, many devices and agents); macOS and Linux only.
  - **License:** BUSL-1.1 source-available (converts to Apache-2.0 four
    years per release) — source-visible but not OSI open source. Same
    family of trade-off HashiCorp made; stated here so nobody discovers
    it in the fine print.

---

## The capability matrix

| Capability | `.env` | direnv / mise | Doppler / Infisical | Vault | `op run` | aws-vault | byn |
|---|---|---|---|---|---|---|---|
| No plaintext secret files at rest | ✗ | ✗ (◐ with sops) | ✓ | ◐ (`~/.vault-token`) | ✓ | ✓ | ✓ |
| Runtime injection by name | ✗ | ◐ (ambient env) | ✓ | ✓ | ✓ | ✓ (AWS) | ✓ |
| Works offline / no cloud account | ✓ | ✓ | ✗ | ◐ (self-host) | ✗ | ✓ | ✓ |
| Per-access audit **on the dev box** | ✗ | ✗ | ✗ (server-side) | ✗ (server-side) | ✗ | ✗ | ✓ |
| Per-terminal session gating | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Per-command pinned allowlist | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Agent-mode hard-fail (no gameable prompt) | — | — | ✗ | ✗ | ✗ | ✗ | ✓ |
| Short-lived derived credentials | ✗ | ✗ | ◐ (rotation) | ✓ (dynamic) | ✗ | ✓ (STS) | ✗ planned |
| Team / org sharing & RBAC | ✗ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ (single-owner by design) |
| Prod / CI / deploy delivery | ✗ | ✗ | ✓ | ✓ | ◐ | ◐ | ✗ not the goal |
| Maturity / third-party audits | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ young |

✓ = yes · ◐ = partial/conditional · ✗ = no. Last two rows are where the
*other* tools win — kept in the table for exactly that reason.

---

## How to read this table

The right column-pattern matters more than any single row. The platform
tools win every **delivery** row (prod, CI, teams, maturity) and lose
every **dev-box containment** row (local audit, session gating, command
allowlist, agent hard-fail). byn is the mirror image. That's not a
ranking — it's two different problems. The realistic best posture for a
team today is honestly: **a platform tool for the pipeline, byn for the
laptop** — and short-lived credentials (Vault dynamic secrets,
aws-vault STS today; byn's planned broker) wherever you can get them.

---

*Tool capabilities are re-verified when this page is re-stamped at each
byn release. If a vendor ships something that changes a row — or you
think a characterization is unfair — open an issue; accuracy outranks
advocacy here.*
