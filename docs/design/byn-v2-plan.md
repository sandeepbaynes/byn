<!-- Design record. Written 2026-07-30, kept current as work lands. The
     status table under "Build order" says what is shipped; the sections
     above it are the reasoning, including the parts an experiment later
     disproved. Those are left in deliberately — the correction is the
     useful part. -->

# byn v2 — ground-up redesign

## Context

A month of real use with privsep on proved byn v1 slows dev down. Quantified from 56 agent transcripts (201 MB): **215 EACCES, 104 EPERM, 118 "Operation not permitted", 101 `make byn-trust` references, 31 master-password prompts.** The project grew a whole workaround layer: `make byn-trust` after every `.byn` edit, cache resets before `dev-all`, ~100 lines of kill-wrapper shell, `sudo rm -rf .next` rituals. Root causes:
1. Trust pins file bytes + mtime; exec capability freezes var names at grant → every edit is a password re-trust, new vars silently missing.
2. Files created by `_byn-exec` aren't owned by the user → EACCES on builds, undeletable caches.
3. `kill`/`ps` on `_byn-exec` processes → EPERM.
4. Non-TTY agents get no session and no non-blocking approval path → they stall.

**User decisions:** ground-up redesign; only the vault survives (with migration). Rethink exec isolation itself. Add an E2E-encrypted sync server (self-hostable open source + byn-hosted commercial, same codebase) and an Expo mobile app (push approvals, console feed, on-the-fly value edits). New vars via `byn put` auto-flow, no approval. Approval channels: terminal + portal + mobile.

---

# Field research (2026-07-30) — what similar tools taught us

Workflow: 7 web-research lanes (secrets CLIs, Vault/cloud, rootless userns, sandbox UX, agent leaks, push fatigue, E2E sync) + 3 adversarial critics vs this plan. Full findings: session task output `wt7axlq01.output`.

**Validates our core bets:** local-first daemon with no network on the exec hot path (Doppler hangs 60s offline; 1Password ~1s/call; Azure cred chains 15s–3min); opaque-bytes env injection at execve (dotenv-family quoting corrupts `$`/backtick passwords); NOT unsharing netns (localhost breakage kills adoption); non-blocking machine-readable approval queue; trust-as-policy; content-free push with pollable queue as truth; LWW + version history; Vault's own CLI leaves `~/.vault-token` plaintext same-UID-readable — our isolation premise is the industry's admitted gap.

**Hard lessons adopted (changes below are tagged [R]):**
1. subuid/userns stack fails on 4 independent axes in the field (LDAP/AD no-subuid, AppArmor userns bans on Ubuntu 23.10+, neutered newuidmap, per-filesystem idmap support) → live probes + enumerated degradation tiers + policy files in packages.
2. Push-approval fatigue is an exploited attack class (Uber/Cisco push-bombing; 93% approval rate in Claude Code) → rate limits, coalescing, risk ladder, number-matching enrollment.
3. Push transports lag minutes-to-hours → generous TTLs, idempotent resolution, reconcile-on-open.
4. Sandboxes die by unattributed denials, git first (worktree `.git` outside project) → denial log + doctor attribution + VCS-aware default policy.
5. Key rotation/migration have total-data-loss precedents (Bitwarden #7709, hot-copied SQLite) → transactional + verified backup, always.
6. One-shot recovery codes brick users (Tailscale, Bitwarden "delete your account") → verified recovery ceremony + device-quorum option.
7. Agents print injected env under prompt injection regardless of advisory filters → output-side leak detection now, egress-proxy substitution tier as design spike.
8. Sessions/grants must survive upgrades (Infisical logs out on rpm upgrade; teller's broken 2.0 rewrite killed it) → never mass-invalidate on migration; v1 verbs stay aliased.

# Spike result (2026-07-30) — A1 corrected by experiment

Built `cmd/sandbox-spike` and ran it on this Fedora 44 box (kernel 7.0.12, Landlock ABI 8, subuid 524288:65536, newuidmap has `cap_setuid=ep`, SELinux enforcing, btrfs). Modes: `probe`, `verify`, `killtest`, `attack`.

**What works (proven):** target runs at a subuid kuid; `/proc/<pid>/environ` and `/proc/<pid>/mem` are unreadable from the real UID; secrets are injected over an fd and confirmed present in the child; artifacts (`.next/`, files) come back **owned by the real user** after the ns-root sweep and `rm -rf` works without sudo. A negative control confirms an unsandboxed process leaks the same secret to any same-UID reader, so the test measures what it claims. Ambient capabilities are the rootless trick that makes the shim work (caps are otherwise wiped by its own `execve` before the uid maps exist).

**What breaks the design (proven, exit code 2 on `sandbox-spike attack`):** a user namespace grants **every capability to the uid that owns it**, and the owner is whoever created it. With `byn exec` (running as the user) creating the sandbox, a same-UID attacker just runs `nsenter -t <pid> -U -p -m` , lands as inner-root, and reads `SPIKE_SECRET` straight out of the target's environ. Direct `/proc` reads being blocked is a decoy — it looks secure and isn't.

**Correction, now binding:** the sandbox namespace must be created by a process at a **different uid** — the daemon under its own service user (`NS_GET_OWNER_UID` must not equal the caller's uid). A user-created namespace is an ownership-convenience tier only, never a security tier. This keeps v1's separate-service-user requirement; the v2 gains (user-owned files, kill cascade, trust-as-policy, approval queue) are unaffected.

# Part A — local core

## A0. Zero-setup principle (user requirement)

**There is no `byn setup`.** Install byn → it works. All privileged or stateful steps are either absorbed into package install or deferred to the moment the user's data needs them:
- First CLI call auto-starts `bynd` as a systemd *user* service (no root needed).
- First vault access with no password set → inline prompt: "set a password for your default vault" → continue. Default vault/project/env auto-created. This is *data* setup, not byn setup.
- Sandbox on by default. [R] Subuid resolution via libsubid/`getsubids` (SSSD/LDAP-served ranges), falling back to `/etc/subuid` parsing; probe with the NSS-resolved username (incl. `user@domain`). No-subuid (enterprise LDAP/AD machines — a first-class tier, not "rare") gets a one-command remediation (`usermod --add-subuids` text or byn's privileged allocator) and a working degraded tier meanwhile. `byn doctor` names which source produced the range.
- **The privileged bits ride the package install** (`dnf/apt install` is already root — still no separate `byn setup` command): the daemon's service user (required for isolation — see spike result) and the idmapped-mount broker `byn-mount-helper`. Tarball/no-root installs run in an honest ownership-only tier.
- [R] **Degradation ladder — enumerated, live-probed at start, reported in `byn status`/`doctor`, never silent. Only tiers whose namespace owner ≠ the caller's uid protect secrets:**
  1. **daemon-owned userns + idmapped mounts** — full: secrets isolated, files user-owned.
  2. **daemon-owned userns + journaled chown-sweep** — full isolation; ownership via sweep (filesystem lacks idmap support).
  3. **user-owned userns (no service user, e.g. tarball install)** — *no secret isolation*: any same-UID process can `nsenter` in. Fixes file ownership only; byn must say this in plain words at every exec and in `byn status`.
  4. **none** — loud warning.
  Probes are live operations (unshare + write uid_map, attempt MOUNT_ATTR_IDMAP on the project's own filesystem, assert `NS_GET_OWNER_UID != getuid()`), never version/stat checks.
- The chown-sweep is journaled/resumable (interrupted sweeps must not half-convert a workspace — systemd-nspawn precedent), and `byn uninstall`/`byn repair` guarantee no subuid-owned files remain on disk.
- [R] **Ubuntu 23.10+/24.04:** unprivileged userns is AppArmor-restricted — the .deb ships an AppArmor profile with a `userns,` rule (as Chrome does); tarball installs detect `apparmor_restrict_unprivileged_userns=1` and degrade to tier 3 with the named fix ("install the package or the profile") — never advise flipping the sysctl. (Both tiers 1 and 2 are userns-based, so a bare tarball on stock Ubuntu 24.04 lands on tier 3; the out-of-box test below reflects that.)
- [R] **newuidmap fragility:** audit the bynd user unit for hardening directives implying NoNewPrivileges; doctor live-probes newuidmap (nosuid mounts, WSL2 tarball imports strip setuid/file caps — offer setcap remediation). Non-systemd environments (WSL2 default, CI, containers): keep a direct-daemonize path; document `loginctl enable-linger`.
- [R] **Filesystem preflight:** statfs project + state dirs; NFS/CIFS/FUSE/9p (`/mnt/c` on WSL2) detected explicitly. On NFS the chown-sweep ALSO fails (server rejects chown to unmapped subuids) — correct degradation is tier 3 with a loud warning. byn's own namespace-written state (vault, approvals.db, sandbox scratch) auto-relocates to local storage when $HOME is networked. Per-workspace (not global) tier decisions.
- [R] **SELinux (Fedora — our dev platform):** ship an SELinux policy module in the RPM (bynd userns, mount-helper ops, socket paths); CI runs enforcing; doctor surfaces byn-related AVC denials via ausearch (denials characteristically appear after `dnf system-upgrade`).
- First `byn exec` in a project = first trust: answered inline on a TTY, or queued (phone/portal/`byn approve`) when an agent triggers it.
- Auth hardening (passkeys), extra vaults/envs, sync server, device pairing: all later, incremental, user-driven.

## A1. Exec isolation: rootless subuid userns + idmapped mounts (replaces two-user model)

Why: at the same kernel UID, `/proc/<pid>/environ`/`mem` are readable by any same-UID process — protection requires a different kuid. v1 used a second real user and broke file ownership; v2 gets a different kuid *without* losing ownership:

- **No setup command** (see A0): uses the distro-default subuid/subgid range; `byn-mount-helper` (small setuid broker whose only job is creating idmapped mounts of caller-approved paths, fd returned over SCM_RIGHTS) ships with the package; rootless dual-map + chown-sweep fallback when absent.
- **Daemon `bynd` runs under its own service user** (package-created) and is the **sole creator of sandbox namespaces** — proven necessary by the spike: the namespace owner holds all capabilities inside it, so a user-created sandbox is `nsenter`-able by any same-UID attacker. The daemon's own memory (vault key) is likewise not ptraceable by the real UID.
- **Per-exec sandbox is spawned by the daemon**, not by the user's `byn exec` process; the wrapper only relays signals and stdio (see kill/ps below). Every exec asserts `NS_GET_OWNER_UID(child) != caller uid` before injecting secrets — a hard runtime invariant, not a comment.
- **Per-exec sandbox `byn-sandbox`:** CLONE_NEWUSER|NEWPID|NEWNS; fresh /proc (host view of `environ`/`mem`/`fd` blocked — different kuid); private /tmp; **Landlock** limits fs to project + policy-declared paths; no_new_privs + seccomp; env map delivered over a socketpair fd (never argv/disk/procfs); execs target.
- **Ownership fix:** project dir bind-mounted as an **idmapped mount** — on-disk uid = the user, bidirectionally. `.next`/`.vite` land user-owned; plain `rm -rf` works. Proven mechanism (rootless containers/systemd). [R] Support is **per-filesystem, not per-kernel** (NFS: never; tmpfs: 6.3+; ZFS: OpenZFS 2.2+; overlayfs edge cases fail silently) — so the probe is a real MOUNT_ATTR_IDMAP attempt on the filesystem hosting each project, decided per-workspace at trust/exec time.
- [R] **Sandbox policy must fit real toolchains before shipping:** default Landlock policy resolves and includes VCS metadata living OUTSIDE the project tree — `git rev-parse --git-common-dir` (linked worktrees keep `.git` under the main repo), submodule gitdirs — plus curated package-manager/tool-state paths. Git commit/rebase/worktree and a pnpm/turbo dev-server run are acceptance tests. (Every sandbox studied broke git first; that's how users learn to disable the sandbox.)
- [R] **Denials are attributable, never mysterious:** a denial log ("byn denied <exe> writing <path> 2s ago"), machine-readable denial errors that point agents at the sanctioned path (`run byn approve <id>`), and `byn doctor exec -- CMD` replay mode attributing a failure to the specific policy rule. A block should generate an approval request, not a bug report.
- **kill/ps fix:** `byn exec` stays a normal user-owned foreground process owning the TTY; relays signals into the sandbox; mutual teardown on either side dying. Makefiles/turbo just work. (`strace` of the inner process stays EPERM — intrinsic: anything the user can inspect, an attacker can too.)
- **Bonus:** sandbox is bidirectional — agent builds can no longer read `~/.ssh`/`~/.aws` unless policy mounts them.
- [R] **Sandbox composition:** detect when the child is itself a sandboxing tool (claude, codex, bazel) or byn is already inside a container/userns — cooperate or report reduced guarantees explicitly; never nested-fail opaquely or downgrade silently. `byn exec -- claude` is the headline use case, not an edge case. Nested tier: fit the mapping inside an already-delegated reduced range (devcontainers/CI); K_cap on machines without a stable hardware id gets an opt-in file-backed floor so container agents don't fall to password-per-run.
- [R] **Rotation story for long-lived processes:** env injection is snapshot-at-exec; agents run dev servers for days. `byn ps` flags staleness ("holds DB_URL injected 3d ago, since rotated"); `byn exec --watch` re-execs on allowlisted value change (or documented SIGHUP hook); "rotated while N processes hold old value" is a surfaced event.
- [R] **Output-side leak detection:** byn owns the child's stdio — scan stdout/stderr for injected secret values; a match is a compromise event (audit + approval-queue card proposing rotation). Design spike for the **egress-proxy substitution tier** (placeholder in env, real value swapped at a byn-owned egress for allowlisted hosts — the 1Password-for-Claude/Cloudflare pattern; only structural answer to "the agent prints env", pairs with the sandbox forcing egress).
- **macOS:** keep refined two-user model (v1 darwin privsep reused) + inherited default ACLs at trust time for the ownership pain; documented best-effort tier. [R] Seatbelt does not nest and sandbox-exec is deprecated — detect agent-CLI children, degrade honestly, track as platform risk. Full degradation ladder + environment preflight: see C1 (research-driven, binding).
- **Never unshare the network namespace by default** — localhost/dev-server breakage is the fastest way to lose users (podman/sandbox research).

## A2. Trust v2 — policy, not bytes

`.byn` becomes a policy *request manifest*; trust attaches to project + granted policy:
- TrustRecord: project_key (canonical root + git remote hash), scope, policy {env_grants (patterns like `"*"`/`APP_*`/names), exec allowlist, mounts, network, auth}, policy_hash, reuse of v1 FPMAC/VKMAC (`internal/trust/mac.go`).
- **Zero prompts for:** any edit whose parsed policy ⊆ granted; value changes; `byn put NEW_VAR` matching a granted pattern (instantly execable).
- **Approval only for:** first trust; widening (computed as a set-diff, shown verbatim); auth downgrades; machine-fingerprint change.
- **Capabilities stay current via key schema change:** add `K_env = HKDF(vaultKey, vaultID‖projectID‖envID)`, `K_row = HKDF(K_env, kind‖name)` (`aad_version=3`). Pattern grants seal **K_env**, so the locked daemon derives keys for rows created after grant — new vars flow forever, no re-grant. Explicit-name grants seal per-row keys, auto-refreshed on `byn put`.

## A3. Approval queue (non-blocking, three surfaces, fatigue-resistant)

- Separate `approvals.db` (works while vault locked): id, kind, project_key, policy_diff JSON, requestor {pid, exe_sha, cwd}, status, decided_via, decision_sig; machine-key MAC.
- IPC: `approval.list/get/decide/wait(long-poll)/subscribe` (feeds portal SSE + sync bridge).
- **Agent semantics:** widening request enqueues and returns immediately with the id (JSON on non-TTY). `byn exec` runs now with the already-granted subset + notice; `--strict` fails with distinct exit code; `--wait-approval[=30s]` for agents that prefer blocking. No hidden TTY prompts, ever. [R] States are machine-readable and distinguish pending / approved / denied / expired **with reason**, so agents wait informatively.
- [R] **TTLs & idempotency (push lags minutes-to-hours):** validity windows default tens-of-minutes-to-hours, configurable; re-request re-attaches to the existing pending record (no duplicates); resolution is idempotent and replay-safe (stale doorbell after resolution is a no-op).
- [R] **Anti-push-bombing / anti-fatigue (Uber/Cisco precedent; 93% approval-rate data):**
  - Per-origin rate limit on enqueue (an agent can call byn in a loop).
  - Coalesce identical pending tuples (project + diff hash) into one card.
  - Risk ladder: previously-approved tuples auto-allow; only novel/anomalous requests demand active input; after N denials of the same tuple → cooldown + escalation to code-entry (number-matching style).
  - One-tap **lockdown** on the approver surface: freezes the requesting workspace, logs a tamper event.
  - Cards show a **semantic diff** against last-granted policy (reuse the trust diff engine), never a raw hash; high-risk grants (`env="*"`, new interpreter, network enable) are visually and interactively distinct.
- Decision auth: terminal (session/password/passkey), portal (existing WebAuthn), mobile (device-key-signed payload over id‖policy_diff_hash‖verdict — daemon verifies; server untrusted). [R] Optional `device-required` policy: once a device is enrolled, the terminal-password path for approvals can be disabled per-vault (an agent that keylogged the master password must not be able to answer its own request); password-resolved approvals are rate-limited and loudly audited regardless.
- On approve: policy updated, capability resealed; if vault locked and reseal needs vaultKey → `approved-pending-materialize`, completes on next unlock (pattern-widening under an already-sealed K_env materializes immediately).
- [R] **No irreversible action rides a config flip** (Bitwarden-rotation-shaped bugs): destructive operations (version purge, vault delete) require explicit typed-confirmation verbs + automatic pre-operation backup.

## A4. Repo layout & reuse

```
cmd/bynd, cmd/byn (incl. exec wrapper), cmd/byn-sandbox, cmd/byn-mount-helper (only setuid code)
internal/vault      REUSE ~90% + v5 migration + K_env    internal/vault/crypto REUSE verbatim
internal/trust      REWRITE policy model, REUSE mac.go   internal/sandbox      NEW
internal/approval   NEW                                  internal/syncbridge   NEW
internal/daemon     REWRITE dispatch/exec; REUSE sessions, peercred, caller
internal/{ipc,fdpass,machineid,paths,config,audit,secmem,passkey} REUSE light-touch
internal/ui         REUSE portal/passkey + ADD approvals page
DROP: Linux two-user path, acl_linux.go, byn-exec-helper, byte-pinning verify (darwin privsep kept for macOS)
```

## A5. Vault migration (schema v4 → v5) — transactional, never lossy

Same SQLite file format. [R] `byn migrate` snapshots via the **SQLite backup API / VACUUM INTO** (never a file copy of a live WAL db — documented silent-corruption mode), verifies the copy's integrity BEFORE touching the original, keeps a timestamped pre-migration backup with a documented rollback, and refuses to run against network filesystems. Argon2id blob, passkeys, entry_versions, audit chain untouched. **Lazy row-key migration:** old rows stay `aad_version=2` (readable forever); writes re-seal at v3 (K_env). Pattern-grant capabilities carry K_env + shrinking snapshot of legacy per-row keys.
[R] **Upgrade-compatibility rule (Infisical/teller lesson):** format bumps auto-migrate records in place and never mass-invalidate grants, sessions, or passkey wraps; forced re-trust is reserved for genuine security-boundary changes and batched (one auth for all). v1 CLI verbs stay aliased in v2. v1 `trusted_byn.json` is the one exception (byte-pinning model is dead) — `byn migrate --propose-trust` pre-fills the approval queue so it's one `byn approve --all`.
[R] New verbs: `byn backup` / `byn restore` using safe snapshot primitives, verified restore path; GC with early warnings for per-operation artifacts (decided/expired approvals, revoked-device records, legacy key snapshots) so no hard cap is ever hit with recovery itself blocked (Tailscale tailnet-lock precedent).

---

# Part B — sync server + mobile

## B1. Why it composes
`K_row` derivation (`internal/vault/crypto/rowkey.go`) has no machine binding — row ciphertexts are machine-independent. Any device with the vault key writes byte-identical blobs. Sync ships ciphertext as-is.

## B2. Topology
Daemon ⇄ server: outbound HTTPS + one WebSocket (approval decisions, sync pokes); no inbound ports; daemon fully offline-capable — server is a mailbox, never an authority. Phone ⇄ server: HTTPS + push wake. Server stores ciphertext only: record blobs + versions, client-signed append-only device log, approval envelopes (detail encrypted), encrypted console ring (TTL), push tokens.

## B3. Keys & devices
- vault_key additionally derives K_meta (names/paths encrypted server-side — server never sees entry names), K_id (HMAC opaque record IDs), K_log (console/approval detail), and wraps a new user_root_key (Ed25519).
- Every device has an on-device Ed25519 key (phone: Secure Enclave/Keystore). Device records cross-signed in a chain rooted at user_root_key — server relays the device log, cannot mint devices. Capabilities: `approve` (sign only) vs `full` (holds wrapped vault_key).
- Phone writes: biometric-unwrap vault_key, derive K_row identically (audited TS/WASM port of rowkey.go+encrypt.go with cross-impl test vectors), sync down as a normal row write.
- Signed approval `{approval_id, vault_id, request_hash, decision, scope/ttl, device_id, seq, issued_at, sig}` — daemon accepts iff sig chains to root, device unrevoked, request_hash matches its own hash (server can't swap requests), seq unseen. First valid decision wins across surfaces. **Unify this canonical request payload with A3's policy_diff hash.**
- Pairing: `byn device pair` → QR {server_url, one-shot token, pairing_secret (never touches server)}; fingerprint-words confirm. [R] **Enrollment is an active challenge, not a tap:** the existing trusted surface displays a short code that must be entered on/matched with the new device (number-matching — a fatigued tap must not be able to enroll an attacker's phone), enrollment attempts are rate-limited with cooldown, and every enrollment/revocation broadcasts loudly to all enrolled surfaces. QR failures get auto-regenerated codes + a manual numeric fallback; pairing errors are distinguishable (network vs expired vs rejected).
- [R] **Recovery is a mandatory verified ceremony (zero-knowledge lockout is the #1 user catastrophe):** recovery codes generated at vault creation, user re-enters one before setup completes (never one-shot scroll-by output — Tailscale/Bitwarden precedent); `byn recovery verify` re-checks; optional device-quorum recovery (N enrolled devices restore access).
- Revocation: signed tombstone; revoking a full device prompts vault-key rotation. [R] **Rotation is transactional and sync-validated (Bitwarden #7709):** refuse unless the initiating device proves a fresh complete sync; automatic pre-rotation backup; other writers revoked atomically at rotation, not trusted to notice.
- Conflicts: LWW on (lamport, wall_time, device_id), losers kept in entry_versions. Schema v5 adds lamport/origin columns. [R] Cross-impl (Go↔TS) test vectors include a hostile-value corpus — `$`, backticks, nested quotes, newlines, UTF-8, leading/trailing spaces, multi-KB binary — through the full put→store→sync→phone-edit→inject round trip.

## B4. Server & push
Go, single static binary/container; SQLite (WAL) self-host default, optional Postgres hosted. Device auth: Ed25519 challenge → short bearer. API: enroll start/claim/result; devicelog get/append; records batch get/put + versions; approvals create/list/decision; console post/get; push/register; /ws. Push: content-free ({type, approval_id}) via Expo Push (works self-hosted with official app build); UnifiedPush fallback + pull-on-open; hosted tier may use FCM/APNs directly behind a PushProvider interface. [R] Push is a wake signal only, never load-bearing: the app reconciles against the server queue on every open; Expo routing through Expo's cloud is documented for self-hosters (content-free but still a third-party disclosure) and optional behind PushProvider; UnifiedPush is treated as best-effort (hours-late under Doze), never the sole path. Self-hosted backup/restore of the server DB is a shipped, verified verb — not a wiki page.

## B5. Expo app MVP
Pair (QR + fingerprint words) · Approvals inbox (push badge, decrypted detail sheet, FaceID gate) · Console feed · Vault browser/editor (masked, biometric reveal, full devices only) · Devices & settings (revoke).

## B6. Compromised-server exposure
Sees: email, device/vault counts, blob sizes/timing, approval frequency/outcome, push tokens, IPs. Never: values, names, paths, console text, approval details. Can deny/delay; cannot forge approvals, enroll devices, or swap requests. Mitigations: size-bucket padding, HMAC record IDs, short console TTL, TOFU server-key pinning.

---

# Part C — cross-cutting requirements from research (the rest are inline as [R])

- **Escape hatch stays out of the agent's reach:** disabling the sandbox is itself an approval-queue action, never a flag on the agent's own tool surface (Anthropic sandbox-runtime#97: the agent flipped its own disable flag to read a deny-listed SSH key).
- **Hot path is sacred:** all N secrets for a command resolved in one ms-scale local IPC batch; never a network hop on the exec path (1Password ~1s/call, Doppler 60s offline hang are the cautionary tales).
- **Injection precedence is a contract:** vault vs inherited env vs .env precedence documented, regression-tested, with a visible warning on key collision (Doppler silently inverted precedence in a release; silent wrong-value beats no error only for attackers).
- **Offline unlock is unconditional and free forever** (Proton Pass's paywalled offline mode is its most-cited flaw).
- **macOS FDA is advisory:** precise per-path error at read time; never refuse to start the daemon over a per-directory capability.
- **Anti-fatigue is architectural, not UX polish:** volume reduction first (durable grants + auto-approve previously-seen tuples), then escalation only for novelty — the 93%-approval data says everything else decays into rubber-stamping.

# Build order

**Shipped so far (2026-09-02, released as v0.6.0).** Items 0–4 are done,
verified live, and the suite is green. Item 6's portal half is done, and the
approval system has since grown the asker's side and reached all three surfaces
— terminal, portal and TUI.

The version step from the 0.5.x line is deliberate. Those were patches for bugs
found by using byn; this one adds a command, two flags, two IPC operations and a
TUI pane, which is a different kind of change and should not be numbered like a
fix.

| # | Item | State |
|---|---|---|
| 0 | env-inheritance fix | `bf5363c` |
| 1 | sandbox spike | `51e3b24` — proved the mechanism AND its ownership flaw |
| 2 | vault v5 + K_env | `6105e32` |
| 3 | trust v2 policy + diff | `01e39b3` |
| 4 | approval queue + non-blocking exec | `0be4350`, `6391b91` |
| 6a | portal approvals page | `498bdc6`, `6f8468d` (audit) |
| 4b | asker-side approvals: watch ticket, instant callback, cancel, reason delivery | `3ce76b0`, `c36cf2a` |
| 4c | agent-requested single use (`byn exec --once`), approver override (`--always`) | `345860a` |
| 4d | approvals on every surface — portal decisions + history + revoke, TUI pane (`g p`) | `ccd466e`, `9068435`, `268844b` |
| — | v1 fixes found by using it | `d95f8a1`, `4dd6914`, `e9fca64`, `7b7778e` |

Some rows cite fewer commits than the work took. History has been rewritten
twice — once to scrub external references, once to add a missing DCO sign-off —
and the hashes those rows used to carry no longer name anything. Where the
commit could be identified again by what it changed, the row now cites the
current hash; where it could not, the hash is dropped rather than replaced with a
guess. A wrong hash in a plan is worse than a missing one, because it reads as
checkable and is not.

Verified end to end: an API server starts under `byn exec` with zero
missing-variable errors and tears down with no orphans. The approval callback was
verified against a live daemon by raising a real request, blocking on it, and
having a person answer — which is how the 60-second client timeout was found,
after the integration test had passed throughout because its decisions came back
in under a second.

**What using it keeps teaching.** Every defect in the fixes column above was
found by running byn, not by testing it. The pattern is consistent enough to be
worth stating: a unit test proves a piece works, and the failures have all been
in the joins between pieces. `/approvals` had a correct route parser, a correct
renderer, and no branch connecting them (`268844b`). A watch had a correct daemon
handler and a client that hung up first (`c36cf2a`). An ACL reconcile did correct
work and repeated it before every exec (`d95f8a1`). None of those is visible from
inside the unit that owns it.

**Still open:** item 6b (sync bridge), 7 (byn-server), 8 (Expo app), 9 (macOS
tier), 10 (egress-proxy spike). Item 5 (first-run lazy init / zero-setup) is
partly done: `byn setup` is no longer a thing the user has to know about — the
installer runs it, and it can elevate itself — but privsep provisioning still
happens through it rather than lazily on first touch.

**TUI parity is now its own piece of work.** The TUI can answer approvals, but
the portal still has a dozen things it does not: trust management, vault/project/
env rename and delete, config read and validate, `.byn` read/write/simulate,
daemon reload/restart, lock/unlock, and vault password change. Passkeys stay
browser-only. This is a project rather than a follow-up and should be scoped as
one.

**Resolved since this was written.** *Alias exec bypasses privsep* — it did, and
it now does not. `byn exec <alias>` asks the daemon to expand the alias before
the CLI resolves a target (`resolveAliasArgv`, an ExecPreflight call that queues
no decision and spends no grant), so an alias runs under privilege separation
like any other command. The protocol change it was waiting on turned out to be a
preflight, not a redesign.

One deferred decision worth revisiting:
- **Explicit-name grants still freeze to their list.** Only `"*"` auto-flows.
  ~~Conservative on purpose; revisit if it produces approval churn in practice.~~
  **Revisited — it did.** Every variable an agent introduced stopped its own
  run. Explicit lists now auto-flow a variable the *caller itself created*:
  self-authored grants (`internal/trust/authored.go`), recorded at `put`,
  MAC-bound, and applied at reconcile when the value was created after the
  grant, has never been overwritten, and the command runs under the same origin
  that created it. The capability is re-sealed at `put` so a locked daemon can
  still inject it. Pre-existing secrets, overwritten values, and other origins
  are unchanged — they are real widenings and still queue.

  The origin is the creating caller's parent process, matched by walking the
  requester's ancestors. Session ids do not work: agent harnesses start each
  tool call in a fresh session, so two calls from one agent do not share one.

- **Writing to a LOCKED vault** (`internal/vault/authored.go`). Requiring an
  unlocked vault for `byn put` was the deeper version of the same mistake: it
  left an unattended agent one option, leaving the vault open, which exposes
  every secret instead of the ones the agent writes. A scope now has a second
  key, `K_auth = HKDF(vaultKey, scope‖"authored")`, sealed into every exec
  capability under the machine key. A locked daemon can write with it and read
  back what it wrote; it opens nothing that already existed, because those rows
  derive from `K_env` and no amount of `K_auth` yields it. Entries written this
  way carry `aad_version = 4`, and the master password still opens them.

  The line for all three exemptions (read, replace, inject-without-approval) is
  **unattended**: no session, no password, no presence token behind the write.
  A value stored by an authenticated caller was protected by that credential
  from the start and keeps needing it, so unlocking in one terminal still grants
  nothing in another. Deciding on the caller rather than on lock state also
  keeps one agent's behaviour identical whether or not someone has the vault
  open. Every pre-existing authorization test passes unmodified, which is the
  evidence that the line is drawn in the right place.

  The honest cost: a value written unattended is protected by the machine as
  well as the master password. That is inherent — a vault that can accept and
  return values while locked must hold a key that survives locking — and it is
  strictly smaller than the exposure it replaces.

0. **Done (v1):** env-inheritance fix committed as `bf5363c`.
1. **Sandbox spike** — riskiest piece first: prove userns + idmapped-mount ownership end-to-end against the A1 compatibility matrix (Fedora SELinux enforcing, Ubuntu 24.04 package+tarball, WSL2 ±systemd, devcontainer, NFS-homed project), with the live-probe + degradation-ladder logic as the spike's skeleton. Each cell: works, or degrades cleanly with a named doctor remediation.
2. Vault v5 + K_env layer (+ lamport/origin columns).
3. Trust v2 policy model + diff engine.
4. Approval queue + `byn approve` + non-blocking exec semantics.
5. Daemon assembly + first-run lazy init (A0: auto-start, vault-on-first-touch, password-on-first-access) + `byn migrate` (+ `--propose-trust`).
6. Portal approvals page + syncbridge hooks.
7. byn-server (records + devicelog → pairing → approvals relay).
8. Expo app (pair → approvals → vault edit) + push providers.
9. macOS tier.
10. Egress-proxy substitution tier + output-watch (design spike from A1 — after core ships).

# Verification

- **Out-of-box test (clean VM/container):** untar byn into `~/bin` with no root, run `byn put X` → password prompt → value stored; `byn exec -- env` works sandboxed via the chown-sweep fallback (on Fedora; on stock Ubuntu 24.04 the tarball lands on the same-kuid tier with a loud notice — package install restores full tier). Then install the package → `byn doctor` shows the idmapped path active. No setup command anywhere.
- **Sandbox spike acceptance (per matrix cell)** — `cmd/sandbox-spike` already implements `probe`/`verify`/`killtest`/`attack`:
  - `attack` **must exit 0** (namespace-join theft fails). It currently exits 2 for a user-created namespace; that mode is the regression test guarding the daemon-owned-namespace rule forever. Resolve host pids via the shim's child — an inner pid attacked on the host tests an unrelated process and passes for the wrong reason.
  - `verify`: environ/mem unreadable from the real UID; the control proves an unsandboxed process *does* leak; secret confirmed present in the child; `.next/` user-owned after sweep; `rm -rf .next` without sudo.
  - `killtest`: killing only the wrapper tears down shim and target (pdeathsig cascade), no leaked processes.
  - Plus: git commit/rebase in a linked worktree under the default policy; denial of an unlisted path produces an attributable log line + approval hint.
- **Anti-fatigue mechanics:** loop `byn trust` from a non-TTY origin → requests coalesce to one card + rate limit kicks in; N denials of the same tuple → cooldown + code-entry escalation; previously-approved tuple → auto-allowed silently.
- **Hostile-value corpus:** `$`, backticks, nested quotes, newlines, UTF-8, multi-KB, NUL-adjacent values survive put → store → capability → inject byte-exactly (and later the phone round trip).
- **Trust v2:** table-driven tests — edit-with-⊆-policy → no approval; `byn put NEW` under `"*"` → immediately in `byn exec -- env`; widening → queue entry with exact diff; touch/comment/reorder → nothing.
- **Approval flow (agent):** non-TTY `byn exec` with widening → JSON {approval_id}, exit per mode; `byn approve` from second terminal → retry succeeds. Same via portal.
- **Migration:** open a v1 vault copy → all values readable; old rows decrypt (aad v2), new writes seal v3; audit chain verifies.
- **Sync/E2E:** round-trip a value machine→server→phone-sim→machine with byte-identical ciphertext test vectors (Go vs TS); forged approval (wrong key / altered request_hash / replayed seq) rejected by daemon.
- Keep test runs scoped (`go test ./internal/...` per package) — this machine OOM-kills heavy processes.
