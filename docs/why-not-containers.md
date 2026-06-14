# Why byn doesn't use containers

A question security-minded evaluators ask — and should ask: *"Wouldn't
running this in a container be more secure? Other tools use containers
(or Nix, or devcontainers) — doesn't that make them safer?"*

Short answer: **a container's security boundary points the wrong way for
the problem byn solves.** Containers protect the host *from the workload
inside them*. byn has to protect a secret-holding process *from untrusted
code already on the host* — the inverse. For that, a container adds
weight and attack surface without adding protection. The long answer,
including where containers genuinely *do* help (and how to use them
**with** byn), is below.

---

## The threat, restated in one paragraph

byn defends against the **agent-era leak**: coding agents, IDE
extensions, MCP servers, and scripts running **under your own UID** that
read a plaintext `.env`, `~/.aws/credentials`, or SSH key off disk and
silently echo it into chat history, logs, or a commit. The adversary is
not a hostile workload you deliberately sandboxed — it is semi-trusted
code you invited, living in your normal host session, with your normal
permissions. (Full model: [Security model](security.md), "owned by you,
operated by many.")

---

## What a container actually isolates — and in which direction

A container is **kernel namespaces + cgroups on a shared kernel**. It is
a packaging and resource-isolation mechanism, not a hypervisor. Two
consequences matter here:

1. **Containers are not "unexploitable."** Every container shares the
   host kernel, and container escapes are a recurring reality — runc
   CVE-2019-5736 (overwrite the host runc binary), the 2024 "Leaky
   Vessels" runc/BuildKit escapes (CVE-2024-21626 et al.), plus any
   kernel privilege-escalation bug. Projects like gVisor and Firecracker
   exist precisely because plain containers were judged *insufficient*
   as a boundary for hostile workloads. "It's in a container, so there's
   no way in" is not a claim any container runtime makes.

2. **The boundary is directional.** Namespaces hide the host from the
   *contained* process. They do nothing to hide the container from the
   **host**: the host kernel schedules every containerized process, the
   host's `/proc` exposes them, and whoever can reach the container
   runtime's control plane owns every container on the machine.

That second point is the disqualifier. byn's adversary is **on the
host**, running as you. A container around byn's secrets would face the
attacker from its weak side.

---

## "Put the secrets / injection in a micro-container" — examined

The intuitive design — run byn's injection inside a small container,
volume-map the project so your code and tools keep running on the host —
fails three independent ways:

1. **The host owns the container.** Any same-UID process that can reach
   the container runtime can `docker exec` into the container, read its
   environment with `docker inspect`, or read its processes through the
   host's `/proc`. The Docker socket is **root-equivalent by design**
   (mounting the host filesystem is one command away) — and dev-machine
   agents very commonly have Docker access, because building and running
   containers is part of the job we give them. Adding a container
   runtime to the machine *expands* the attack surface byn is defending.

2. **Volume mounts pierce the boundary.** The moment the container maps
   a host volume, anything the injector writes there is plaintext on the
   host disk — the exact thing byn exists to prevent. A boundary with a
   shared-filesystem hole in it is not a boundary for secrets.

3. **The credential must cross back anyway.** The processes that
   *consume* credentials — `aws`, `psql`, your application, the agent's
   build — run on the host in this design. So the plaintext has to leave
   the container (via env, the shared volume, or a socket) at precisely
   the moment it matters. The container protects the secret only while
   nothing is using it — and that case is already covered by the
   encrypted vault.

And on macOS — the primary dev platform for this problem — there is no
native container support: Docker runs a **Linux VM**, so "a micro
container for injection" means crossing a VM boundary plus virtualized
file sharing on every credential use. Heavyweight, slower, and still
wrong-direction.

---

## What byn does instead

The one ingredient of a container that *is* relevant to this threat is
**UID/privilege separation** — and byn takes that ingredient directly,
without the container runtime around it:

- **A separate daemon process** holds the vault key in memory only;
  secret values are AEAD-encrypted at rest and never written to disk in
  plaintext. The process boundary (separate address space) is the same
  kernel primitive containers are built on.
- **Privilege separation** (shipped opt-in in v0.3.0; enable with
  `[security] privsep` + `sudo byn setup`): the daemon runs
  as its own `_byn` service UID and `byn exec` spawns the child as a
  `_byn-exec` UID — so a same-UID agent can no longer connect to the
  daemon socket, ptrace the daemon, or read the child's
  `/proc/<pid>/environ` without root. This is the cross-UID isolation a
  container would have contributed, minus the root-equivalent control
  plane, the VM on macOS, and the per-use latency.
- **Per-terminal sessions and proof-of-presence** gate sensitive
  operations, and **every value access is audited** — so even when
  prevention fails, the leak is detectable.

**The honest ceiling is identical in both designs:** an adversary with
root defeats containers and UID separation alike (root can exec into any
container, read any `/proc`, ptrace anything). No local architecture —
container, VM-per-secret, or privsep — changes that; see "Out of scope"
in the [Security model](security.md).

---

## "But Nix / devcontainers / tool X are isolated…"

Reproducible-environment tools solve a **different problem** —
reproducibility — and are routinely mistaken for secret-confidentiality
tools. Two specifics worth knowing:

- **Nix:** the Nix store (`/nix/store`) is world-readable by design;
  anything a derivation embeds is plaintext for every user and process
  on the machine. The community's own secret-management add-ons
  (agenix, sops-nix) exist precisely because of this — and they decrypt
  secrets onto the filesystem at activation time, which puts a readable
  file back within reach of the same-UID workload. Nix gives you
  reproducible environments, not confidential credentials.
- **Devcontainers / Docker dev environments:** a `.env` file mounted
  into the container is exactly as plaintext as it was on the host —
  and the coding agent you're worried about typically runs **inside**
  that container, right next to the secrets. The container isolated the
  agent from your host, not your secrets from the agent.

None of these are competitors on the leak byn targets. They compose
with byn — which is the next section.

---

## Where containers genuinely help: contain the agent, not the secret

The correct container play is the inversion. Don't put the secret in
the box — **put the untrusted code in the box**:

- Run agents and untrusted tooling in a container, VM, or separate OS
  user account.
- Do **not** mount `~/.byn`, the byn daemon socket, or
  `/var/run/docker.sock` into that sandbox.
- Keep byn on the host. Credentials are injected only into processes
  *you* start via `byn exec`, and the sandboxed agent has no path to
  the daemon, the vault file, or the injected child.

Used this way, the container's boundary finally points the right
direction: host (and byn) protected *from* the workload. This is also
the standing recommendation in the
[Security model](security.md) best practices — with privilege
separation off (the default), a separate UID/sandbox/VM for untrusted
code is the real same-UID boundary, and it remains good
defense-in-depth even with privsep enabled.

---

## Summary

| Design | Boundary direction | Verdict for byn's threat |
|---|---|---|
| Secrets/injection inside a container, volumes to host | Protects host *from container* — attacker is on the host | Wrong direction: runtime control plane is root-equivalent, mounts leak plaintext, creds cross back at use time |
| Nix / devcontainer environments | Reproducibility, not confidentiality | Orthogonal: world-readable store / mounted plaintext `.env`; agent lives with the secrets |
| **byn:** encrypted vault + daemon + UID privsep + audit | Protects the secret-holder *from same-UID code* | Matches the threat; container's useful ingredient (cross-UID isolation) without its baggage |
| **byn + sandboxed agent** (container/VM/separate user) | Both directions covered | Recommended: byn guards the secrets, the sandbox guards the host |

byn isn't container-less because containers were overlooked — it's
container-less because the threat model was taken seriously.

---

## Related

- [Security model](security.md) — full threat model, named limits, best practices.
- [Architecture](architecture.md) — daemon process model and IPC.
- [Integrations: AI agents](integrations/ai-agents.md) — running agents against byn safely.
