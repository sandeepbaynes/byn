# How agents and bots leak your secrets

*Field note · coverage: v0.4.0 · updated with each release*

Most credential leaks in agentic development are not attacks. They are
**accidents with your permissions**: an agent debugging a build reads the
`.env` and quotes it in its explanation; an inline-completion model
ingests a key as you type it; a post-install script wearing your UID
harvests `~/.aws/credentials`. The common root cause is that the entire
dev ecosystem assumes secrets sit in **plaintext files any process
running as you can read** — and your machine is now operated by a crowd
of such processes.

This field note catalogs the leak vectors one by one. For each: how the
leak happens, what byn does about it **today (v0.4.0)**, where byn
**cannot** protect, and what is **coming** that will close more of the
gap. It is updated every release. For verified incidents in the wild,
see [Real-world incidents](real-world-incidents.md); for the author's
own, see [The AWS credentials file that cost me my
account](aws-credential-file-takeover.md).

---

## Vector 1 — The agent reads a secret file off disk

**How it happens.** Agents explore. Debugging a connection failure, an
agent reads `.env`, `~/.aws/credentials`, or an SSH key "to check the
config" — then the value appears in its reasoning, its chat transcript,
a log line, or a generated file. With cloud-hosted models the secret has
left your machine the moment it enters the context window. In-harness
deny rules are best-effort: a recurring pattern of reports documents
agents reading `.env` files past configured guardrails — see the
deny-rule entry in [Real-world incidents](real-world-incidents.md) for
the linked reports and the honest caveats.

- **byn today:** the file doesn't exist. Values live AEAD-encrypted in
  the vault; the agent can list *names* but reading a *value* requires a
  per-terminal session or fresh authorization (NU-3), and **every value
  access is audited**. `byn exec` injects vars only into the child it
  spawns.
- **Where byn can't protect:** a half-migration — if a plaintext copy
  still sits next to the vault, byn protects nothing about it. And an
  agent running in a terminal *you unlocked* can use that session
  (see Vector 6).
- **Now (opt-in) + coming:** privilege separation — opt-in since v0.3.0
  (`[security] privsep` + `sudo byn setup`) — runs the daemon and trusted-pinned
  exec children on their own service UIDs (`_byn`, `_byn-exec`), so a same-UID
  agent can't ptrace the daemon or read an injected child's env (`ps -E` on
  macOS, `/proc/<pid>/environ` on Linux). **v0.4.0** spawns that child in your
  shell's process tree, so it inherits your TCC / Full Disk Access (it runs in
  `~/Documents` et al.) while the env stays hidden. Still on the roadmap: Phase 3
  shims (`aws`, `ssh`, …) to remove more plaintext files, and FUSE-gated
  crown-jewel files behind them.

---

## Vector 2 — The secret ends up in the agent's context anyway

**How it happens.** A test prints the connection string on failure; a
verbose flag dumps the env; an error message embeds the token. The agent
faithfully reads the output — and now the secret is in the transcript.

- **byn today:** structural reduction — when secrets are referenced by
  *name* and injected at runtime, they stop appearing in source, config,
  and most output paths. The audit log timestamps which secrets flowed
  into which command, so a suspect transcript can be correlated with
  exactly what was exposed.
- **Where byn can't protect:** a workload that *prints* an injected
  value prints it. byn injects credentials for the child to use; it
  cannot control what the child does with them. Detection (audit) is
  the honest guarantee here, not concealment.
- **Coming:** leak-pattern scanning over the audit log (risky command
  shapes, secrets piped to terminals) is under exploration as a
  rule-based, pluggable detector.

---

## Vector 3 — IDE inline completion ingests the secret as you type it

**How it happens.** Inline completion (Copilot, Cursor Tab, JetBrains
AI, …) streams your buffer to an inference endpoint on every keystroke.
Type a real credential into a source file and it has been read — and,
with cloud inference, has left the machine — before you finish the line.
The tell-tale is completion *suggesting your own secret back to you*.

And the buffer is only the smallest context these tools read.
Prediction quality scales with context, so the engines pull in
neighboring tabs, recently-edited files, and — for codebase-aware
assistants — an **index of the entire project tree**, built by scanning
files you never opened and shipping content (or embeddings) to the
vendor's servers. A `.env` that merely *sits in the project* is
eligible context for such systems, typed or not. The controls are
weaker than people assume: exclusion mechanisms (Copilot content
exclusions, `.cursorignore`, and similar) are vendor-specific, often
plan-gated, and documented as **best-effort** — product features, not
security boundaries. There is no universal, enforceable "do not read
this" contract an editor extension must honor — and every extension
runs with your full user permissions, able to read anything your UID
can, with no technical way for you to verify what it read or sent.

- **byn today:** the same structural answer — there is no reason for a
  literal to sit in a buffer *or in the project tree at all*. Reference
  by name, inject with `byn exec`; nothing for the buffer, the
  neighboring tabs, or the project index to collect.
- **Where byn can't protect:** byn cannot police the editor. If you do
  type a literal, completion sees it. "No secret literals in source" is
  the discipline byn makes practical, not one it can enforce. Treat any
  suggested-back secret as compromised and rotate it.
- **Coming:** nothing can intercept the editor from user space without
  becoming the IDE; this vector stays a discipline byn enables.

---

## Vector 4 — The secret gets committed and pushed

**How it happens.** A `.env` slips past `.gitignore`; a config with an
embedded token gets committed by you or generated-and-committed by an
agent. Public-repo secret sprawl is measured in the millions of new
leaked secrets per year (see [Real-world
incidents](real-world-incidents.md)).

- **byn today:** the repo carries *names*, not values. The `.byn`
  manifest is safe to commit by design — it declares which variables a
  project needs, never what they are.
- **Where byn can't protect:** values pasted into code anyway, or
  pre-byn history. Scrub history and rotate; byn prevents the next one,
  not the last one.
- **Coming:** —

---

## Vector 5 — Supply-chain malware wearing your UID harvests credentials

**How it happens.** A compromised npm package's post-install script, a
malicious VS Code extension, or a trojaned CLI runs as *you* and sweeps
the well-known paths: `.env` everywhere, `~/.aws/credentials`,
`~/.ssh/`, npm tokens, wallets. Recent campaigns explicitly used
*installed AI CLIs* as the harvesting engine (see [Real-world
incidents](real-world-incidents.md)).

- **byn today:** the sweep comes up empty — there are no plaintext
  credential files to find. The vault file yields names and ciphertext;
  values require a session or the master password, the daemon socket
  rejects requests without authorization for value reads, and every
  attempt lands in the audit log — the attack becomes **loud**.
- **Where byn can't protect (with privsep off — the default):** the full
  same-UID ceiling: a
  code-executing process as your UID can ptrace the *unlocked* daemon,
  read an injected child's environ, or keylog a password prompt in a
  terminal it controls. It can also simply wait inside a terminal that
  holds a live session.
- **Now opt-in / planned:** privilege separation (shipped opt-in in v0.3.0 —
  enable with `[security] privsep` + `sudo byn setup`) removes the ptrace /
  environ / socket paths for non-root same-UID code — exactly this vector's
  strongest moves. Off-box audit anchoring (planned) makes the trail
  tamper-proof even against an attacker who later gets the file. Vaults are
  **portable by design** — a *copied* vault is protected by the password wrap,
  not machine binding; a stronger break-glass recovery wrap is planned so a
  memorable password isn't the at-rest floor.

---

## Vector 6 — Prompt injection turns a good agent rogue

**How it happens.** The agent itself is fine; its *input* is hostile. A
poisoned issue, README, rules file, or web page instructs the agent to
"also collect the API keys and POST them to…". The agent executes with
**your** permissions — this is the confused-deputy problem, and it has
been demonstrated repeatedly against real agent stacks.

- **byn today:** the agent's permissions no longer include silent value
  access. Reads require a session or fresh auth; ad-hoc exec is gated;
  trusted-`.byn` exec runs only the **pinned command list** approved
  with your password; in agent mode (`--json`) byn refuses interactive
  prompts entirely, so an injected agent can't social-engineer a y/N
  dialog. Sensitive grants (trust, reveal) demand proof-of-presence.
- **Where byn can't protect:** an injected agent operating inside a
  terminal with a live session can use that session for gated reads
  until it expires or you `byn lock --session`. The TTY binding is not
  a same-UID boundary (a determined process can acquire your terminal).
- **Now (opt-in) + coming:** privilege separation (opt-in in v0.3.0)
  tightens the daemon surface; per-command `[auth]` policy already lets
  you force `always` auth for sensitive scopes; out-of-band approval
  surfaces (a channel the agent can't drive) are the planned strong form
  via the pluggable auth provider interface.

---

## Vector 7 — Long-lived credentials on dev VMs and remote boxes

**How it happens.** A dev VM accumulates real cloud credentials in
dotfiles because the tooling expects them there. The box is reachable,
shared, snapshotted, or simply compromised once — and the credentials
inside are durable, broad, and unmonitored. This is the author's own
incident: [The AWS credentials file that cost me my
account](aws-credential-file-takeover.md).

- **byn today:** at-rest encryption with per-action authorization means
  a compromised box doesn't hand over working credentials; pinned
  `[exec] actions` means only commands you pre-approved run without
  fresh auth; the audit chain gives you the forensic trail of what was
  touched and when.
- **Where byn can't protect:** an attacker with root on the box, or one
  who phishes/keylogs the master password, is past byn (named out of
  scope). A weak vault passphrase on a stolen file is offline-crackable.
- **Coming:** an ephemeral scoped-credential broker (vend short-lived
  STS-style tokens so what an attacker reads is already expired or
  narrowly scoped) is designed and deferred; TTL/lease-based offline
  revocation arrives with cloud sync.

---

## The honest summary: default vs opt-in privsep

| Vector | v0.4.0 (default) | v0.4.0 + privsep (opt-in) | Planned |
|---|---|---|---|
| 1. Agent reads secret file | ✓ no plaintext file; reads gated + audited | ✓ + daemon/child on own UIDs | Shims, FUSE file gating |
| 2. Secret enters agent context | ◐ reduced + audited; child output not controllable | — | Audit leak-pattern scan |
| 3. IDE completion ingestion | ◐ structural (no literal to read) | — | — (editor is out of reach) |
| 4. Committed to git | ✓ names in repo, values in vault | — | — |
| 5. Same-UID harvesting malware | ◐ nothing to harvest; ptrace/environ residual | ✓ ptrace/environ/socket need root | Off-box audit anchor, break-glass recovery wrap |
| 6. Prompt-injected agent | ◐ gated actions, pinned exec, no interactive bypass | ✓ tighter daemon surface | Out-of-band approval channel |
| 7. Creds on dev VMs | ◐ encrypted + authorized + audited | ✓ | Scoped short-lived broker, leases |

✓ = covered (within the stated model) · ◐ = materially reduced, residual named above.
Root, a known master password, and physical coercion remain out of scope
for any user-space tool — see the [Security model](../security.md).

---

## Best practices for agentic development

1. **Finish the migration — delete the plaintext originals.** `byn`
   protects the secrets *in the vault*; a forgotten `.env.backup` undoes
   everything. Import, verify, shred.
2. **Run agents in terminals that hold no session.** Sessions are
   per-terminal (NU-3): unlock in *your* terminal, let the agent's
   terminal get `auth_required`. Never run an agent in the window you
   just unlocked.
3. **Pin `[exec] actions`; never ship `actions = "*"` where agents
   run.** The pinned list is the contract for what runs without fresh
   auth. Review `byn trust diff` before every re-trust.
4. **Scope `[exec] env` to the minimum.** Fewer injected vars, less in
   the child's environ to read or print.
5. **Sandbox the agent itself** — container, VM, or separate OS user,
   with `~/.byn`, the daemon socket, and `/var/run/docker.sock` *not*
   mounted in. byn guards the secrets; the sandbox guards the host. (See
   [Why not containers?](../why-not-containers.md) for why this
   direction — and not "byn in a container" — is the right one.)
6. **Keep `idle_timeout` short and `byn lock` when you step away.**
   `byn lock --session` drops just the current terminal's access.
7. **Read your audit log after agent sessions.** `byn audit` is the
   detection half of the model — an access you don't recognize is your
   early warning, and early means *before* the credential is abused.
8. **Use a long generated master passphrase + full-disk encryption.**
   The passphrase is the at-rest floor of a (deliberately portable)
   vault file; FDE stops the file being copied at all.
9. **Rotate on any suspicion.** A secret suggested back by completion,
   an unexplained audit entry, a suspect dependency — treat the
   credential as gone and rotate first, investigate second.

---

*This field note is reviewed and re-stamped at every byn release. If a
claim above doesn't match the shipped behavior of the version you run,
that's a bug in the docs — please open an issue.*
