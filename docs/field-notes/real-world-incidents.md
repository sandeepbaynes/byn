# Real-world incidents byn is built for

*Field note · coverage: v0.2.0 · updated with each release*

Every incident below is real, verified, and linked to primary or
reputable secondary sources. For each one we answer three questions
**honestly**:

1. **Would byn (v0.2.0) have changed the outcome?**
2. **Would another credential manager have helped too?** If yes, we say
   so — several good tools remove plaintext files, and pretending
   otherwise would be marketing, not security.
3. **What is byn's specific edge in this scenario**, if any?

Verdict key: ✓ prevented/defanged · ◐ materially reduced or detected ·
✗ byn would not have helped (kept here for honesty — these incidents
shape the roadmap).

See also: [the author's own incident](aws-credential-file-takeover.md),
and the vector-by-vector analysis in
[How agents leak secrets](how-agents-leak-secrets.md).

---

## 1. "s1ngularity" — the Nx supply-chain attack that weaponized AI CLIs — **byn: ✓/◐**

**August 2025.** Compromised versions of the popular `nx` npm package
shipped a post-install payload that scanned victims' disks for GitHub
tokens, npm keys, SSH private keys, API keys, `.env`-style secrets, and
crypto wallets — and, notably, drove **locally installed AI CLIs**
(Claude Code, Gemini CLI, Amazon Q) with flags like
`--dangerously-skip-permissions` to do the filesystem hunting. Loot was
pushed to 1,400+ public GitHub repos; GitGuardian counted ~2,349 leaked
credentials from ~1,079 machines, and stolen tokens powered a second
wave that flipped victims' private repos public.
([The Hacker News](https://thehackernews.com/2025/08/malicious-nx-packages-in-s1ngularity.html) ·
[Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack))

- **byn?** ✓ for the env/API-key sweep: there is no `.env` to find, the
  vault yields ciphertext, and a value read from the malware's shell has
  no session → `auth_required`. ◐ overall: the attempted reads land in
  the **audit log**, turning a silent harvest into a loud one. Honest
  gap: byn v0.2.0 does not hide `~/.ssh` keys or other tools' token
  files (the `ssh` shim and file-gating are roadmap) — those slices of
  the loot were reachable regardless of which env-secret manager you
  used.
- **Other managers?** Yes, partly. Anything that gets secrets out of
  plaintext dotfiles (1Password CLI, doppler, Infisical, keychain-backed
  tools) shrinks this sweep too.
- **byn's edge:** the attack literally ran *agents* against the disk —
  byn's gates are agent-aware: agent mode (`--json`) hard-fails rather
  than prompting, sessions are per-terminal so a malware shell holds
  none, and every attempted access is audited. Most injection tools
  have no per-access audit trail at all.

## 2. Shai-Hulud — the self-replicating npm worm running TruffleHog on your disk — **byn: ✓/◐**

**September 2025** (resurgence Nov 2025). A worm compromised 500+ npm
packages; on install it downloaded TruffleHog, scanned the entire
filesystem for credentials (npm tokens, GitHub credentials, cloud
keys), exfiltrated them to attacker GitHub repos — then used the
victim's own npm token to backdoor up to 100 of the victim's packages
and propagate.
([CISA](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) ·
[Unit 42](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/))

- **byn?** ✓ for secrets in the vault: TruffleHog finds plaintext, and
  there isn't any. ◐ for the propagation step: the worm needed the
  `.npmrc` token — held in byn and injected only for pinned commands,
  the token isn't sitting in a dotfile to copy. Audit shows the attempt.
- **Other managers?** Yes for the storage half — any vault beats a
  dotfile. The worm's success depended entirely on credentials being
  *findable files*.
- **byn's edge:** local-first matters here. The worm ran on dev
  machines, offline-capable; a cloud-vault CLI that caches a token on
  disk to authenticate (ironically, an `.npmrc`-style file) re-creates
  the problem. byn's daemon holds keys in memory, gated per action,
  with nothing reusable on disk.

## 3. Amazon Q extension shipped with a wiper prompt aimed at local AWS credentials — **byn: ◐**

**July 2025.** An attacker slipped a malicious system prompt into the
officially released Amazon Q VS Code extension (v1.84.0), instructing
the embedded agent to wipe local files and destroy AWS cloud resources
**using the developer's locally configured AWS CLI credentials**.
Formatting errors kept the payload from executing; AWS shipped a clean
v1.85.0.
([The Register](https://www.theregister.com/2025/07/24/amazon_q_ai_prompt/) ·
[SC World](https://www.scworld.com/news/amazon-q-extension-for-vs-code-reportedly-injected-with-wiper-prompt))

- **byn?** ◐. The destructive path assumed `aws` *just works* because
  `~/.aws/credentials` is ambient. With AWS creds in byn, an arbitrary
  `aws ec2 terminate-instances …` from a hijacked agent is not a pinned
  action — it hits the authorization gate and fails loudly in agent
  mode. Honest limits: if you pinned broad destructive commands
  yourself, the gate is open; and an agent in a terminal with a live
  session can use it until it expires.
- **Other managers?** Partly. `aws-vault` also removes the plaintext
  file and vends short-lived session creds — genuinely good here. But
  `aws-vault exec` hands a working environment to *whatever command is
  named*; it has no concept of which commands are approved.
- **byn's edge:** the pinned `[exec] actions` allowlist is per-command
  authorization, not just credential storage — exactly the control that
  separates "agent runs the build" from "agent nukes the account." Plus
  the audit trail of what was attempted.

## 4. The pattern of agents reading `.env` despite deny rules — **byn: ✓**

**2025–2026.** Multiple reports document coding agents reading `.env`
files and displaying credentials despite configured guardrails —
e.g. [anthropics/claude-code#24846](https://github.com/anthropics/claude-code/issues/24846)
(deny patterns for `.env*`, `*.pem`, `.aws/` not enforced — note the
reporter used a non-documented config schema and the issue was closed
as a duplicate of a recurring series) and independent write-ups showing
`.env` contents landing in transcripts despite explicit instructions
([Martin Paul Eve](https://eve.gd/2026/04/19/claude-code-can-consume-transmit-and-compromise-your-env-files-even-if-you-tell-it-not-to/) ·
[Knostic](https://www.knostic.ai/blog/claude-loads-secrets-without-permission)).
The fair conclusion is not "agent X is broken" — it is that
**in-harness deny rules are advisory, misconfiguration-prone, and not a
security boundary.**

- **byn?** ✓ — this is byn's core case. The control moves from the
  agent's configuration (which the agent vendor, a typo, or the agent
  itself can defeat) to the OS/daemon: there is no plaintext file, and
  value reads require authorization the agent doesn't have.
- **Other managers?** Yes — any runtime-injection tool (`op run`,
  `doppler run`, Infisical) that lets you delete the `.env` achieves
  the same first step.
- **byn's edge:** the *audit trail* and the agent-aware gates. With
  `op run` or `doppler run`, the injected process tree — and anything
  the agent runs inside it — sees the secrets, and no per-access log
  exists locally. byn logs every value access with caller context, so
  "did the agent touch the prod key?" has an answer.

## 5. GitGuardian's secret-sprawl numbers — the background radiation — **byn: ◐**

**March 2026 report (2025 data).** GitGuardian counted **29 million**
new hardcoded secrets pushed to public GitHub in 2025 (+34% YoY, the
largest jump recorded), with AI-service secrets up 81%; the prior-year
report found ~70% of secrets leaked years earlier were *still active*.
([Report](https://www.gitguardian.com/state-of-secrets-sprawl-report-2026) ·
[GitGuardian blog](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/))

- **byn?** ◐ structurally: a repo built on byn carries *names* (the
  committable `.byn` manifest), not values — there is no literal to
  commit. It cannot fix what's already in history or what someone
  hardcodes anyway.
- **Other managers?** Yes — this is an ecosystem problem, and every
  inject-by-reference tool helps. Pre-commit scanners (gitleaks,
  GitGuardian itself) attack it from the detection side.
- **byn's edge:** byn aims at the *workflow that generates* these
  commits — agents and humans writing config with live values in the
  buffer. No literal in the buffer (see vector 3 in
  [How agents leak secrets](how-agents-leak-secrets.md)), nothing to
  commit.

---

## The wider pattern (honest: byn is not the control here)

These verified incidents shape the threat landscape and byn's roadmap,
but a local secrets vault would **not** have been the decisive control —
listed so the comparison stays honest:

- **tj-actions/changed-files (CVE-2025-30066), March 2025 — byn: ✗.**
  A compromised GitHub Action dumped CI-runner memory, printing
  workflow secrets (AWS keys, PATs, npm tokens) into public build logs
  for 23,000+ repos. That's GitHub's runner, not your dev box — byn's
  domain ends at your machine. The transferable lesson is the same one
  driving byn's roadmap: long-lived ambient credentials are the fuel;
  short-lived scoped credentials (planned broker) shrink the blast
  radius.
  ([CISA](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction) ·
  [Wiz](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066))
- **GitHub MCP prompt injection (Invariant Labs), May 2025 — byn: ✗/◐.**
  A poisoned public issue made an agent leak private-repo data through
  its own over-scoped PAT. The fix is token scoping; byn's contribution
  is only that tokens stored by name aren't *additionally* lying around
  in config files for the agent to quote.
  ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability) ·
  [DevClass](https://devclass.com/2025/05/27/researchers-warn-of-prompt-injection-vulnerability-in-github-mcp-with-no-obvious-fix/))
- **EchoLeak (CVE-2025-32711), June 2025 — byn: ✗.** Zero-click prompt
  injection made M365 Copilot exfiltrate mailbox/SharePoint content.
  Workplace SaaS data, not local dev credentials — included as proof
  that *zero-interaction agent exfiltration is real*, which is the
  class of adversary byn assumes.
  ([The Hacker News](https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html) ·
  [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711))
- **Rules File Backdoor (Pillar Security), March 2025 — byn: ◐.**
  Invisible Unicode in `.cursor/rules` / Copilot instruction files can
  steer agents with instructions human reviewers can't see — including,
  in principle, "collect the keys." byn doesn't stop the injection; it
  removes the easy payoff (no plaintext to collect) and logs the
  attempt.
  ([Pillar Security](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents) ·
  [The Hacker News](https://thehackernews.com/2025/03/new-rules-file-backdoor-attack-lets.html))
- **Samsung ↔ ChatGPT leaks, April 2023 — byn: ✗.** Engineers pasted
  proprietary source code into ChatGPT; Samsung banned generative AI
  on company devices. Human-pasted *IP*, not credential files — the
  earliest mainstream proof that "the AI tool saw it" equals "it left
  the building."
  ([Bloomberg](https://www.bloomberg.com/news/articles/2023-05-02/samsung-bans-chatgpt-and-other-generative-ai-use-by-staff-after-leak) ·
  [Fortune](https://fortune.com/2023/05/02/samsung-bans-employee-use-chatgpt-data-leak/))

---

## How byn compares when the adversary is on your dev machine

Honest framing first: **several tools solve the storage problem.**
1Password CLI (`op run`), Doppler, Infisical, and `aws-vault` all get
secrets out of plaintext dotfiles and inject at runtime — adopting any
of them beats `.env` files. (Full per-tool strengths and weaknesses —
byn's included — in [byn vs the other tools,
honestly](tool-comparison.md).) The 2026 prior-art research behind byn
found no tool, however, that combines all of the following for the
*dev-time agent* threat — which is exactly the combination the
incidents above exploit the absence of:

| Capability | Plaintext files | Cloud secret managers (op/doppler/Infisical) | aws-vault | **byn** |
|---|---|---|---|---|
| No plaintext secret files at rest | ✗ | ✓ | ✓ (keychain) | ✓ |
| Runtime injection by name | ✗ | ✓ | ✓ (AWS only) | ✓ |
| **Per-access audit trail on the dev box** | ✗ | ✗ (server-side org logs at best) | ✗ | ✓ every value access, HMAC-chained |
| **Per-terminal session gating** (an unlock in your shell grants the agent's shell nothing) | ✗ | ✗ (authorized CLI session is ambient to the user) | ✗ | ✓ NU-3 |
| **Pinned per-command allowlist** (only approved commands run without fresh auth) | ✗ | ✗ | ✗ | ✓ `[exec] actions` |
| Agent-mode hard-fail (no interactive prompt an agent can game) | — | ✗ | ✗ | ✓ `--json` |
| Local-first (works offline, no account, no cloud dependency holding your keys) | ✓ | ✗ | ✓ | ✓ |
| Committable manifest of *names* (`.byn`) with tamper-evident trust | ✗ | partial (project config) | ✗ | ✓ TOFU + MAC |

The pattern across s1ngularity, Shai-Hulud, the Amazon Q wiper, and the
`.env`-reading agents is the same: **the attacker's cheapest move is a
same-UID read of an ambient credential, and nothing on the machine
records that it happened.** byn's design goal is that the cheap move
finds nothing, the expensive moves require authorization the agent
doesn't hold, and *every* move leaves a trail.

---

*Sources verified at time of writing (2026-06). This page is reviewed
and extended at every byn release — incident suggestions welcome via
GitHub issues.*
