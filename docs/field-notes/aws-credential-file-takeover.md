# The AWS credentials file that cost me my account

*Field note · from the author · coverage: v0.3.0*

This one isn't from a vendor write-up. It happened to me, on my own
infrastructure, and it is part of why byn exists.

---

## What happened

I ran development workloads on a VM. Like every machine the AWS CLI has
ever touched, it had a `~/.aws/credentials` file — plaintext access key
and secret, sitting at the best-known path in the industry, readable by
any process running as my user.

An attacker got access to that file. I still can't tell you with
certainty which door they came through — and that detail matters less
than people think, because once *any* code ran as my user, the rest was
inevitable: read one file, and they had durable, fully-privileged
credentials. They took over my AWS accounts.

There was no alarm. No log line on the box that said "your credentials
file was read at 03:14." The first signal was the consequences in the
AWS account itself — which means the first signal came *after* the
takeover, not before it.

---

## "You should have used restrictive IAM policies"

Correct — and incomplete. Least-privilege IAM absolutely would have
shrunk the blast radius, and you should do it. But here is the tension
nobody likes to admit: **I develop with autonomous agents because they
are faster than me.** That speed is the point. An agent provisioning
infrastructure, debugging a deployment, or experimenting with services
needs real permissions *now* — and every time a policy is one statement
too narrow, the fast loop stalls while a human goes clicking through
IAM. In practice, dev credentials drift broad because narrow ones tax
the workflow you bought the agents for.

So the realistic dev-box posture was: broad-ish credentials, in a
plaintext file, on a machine operated by processes I don't individually
supervise. That posture is the industry default. It is also exactly
what the attacker needed.

---

## The research: what I looked at before building anything

I didn't jump to "build a tool." I went looking for one. Doppler,
Infisical, direnv, mise-en-place, the cloud vaults, the exec-wrappers —
the landscape is genuinely good at what it targets, and what it targets
is **production**: syncing secrets into deploy pipelines, CI, and
runtime environments. The local dev machine — the place where the
credentials actually sit while a human and a crowd of agents work — is
treated as a solved problem or not a problem at all:

- **Doppler / Infisical** are built around a cloud workspace pushing
  values into environments and pipelines. The local CLI is an access
  path to that cloud, not a defense of the dev box: once the CLI is
  authenticated, any process running as you can use it, nothing on the
  machine records per-access, and the auth token itself is cached
  locally.
- **direnv / mise-en-place** are developer-experience tools: they load
  env vars from files in your project tree. Those files are plaintext
  on disk — exactly the artifact the agent-era leak reads. They manage
  environments; they don't protect secrets from the machine's own
  processes.
- **The exec-wrappers** (aws-vault and friends) genuinely remove the
  plaintext file for their slice, but they authorize *credential
  retrieval*, not *commands* — whatever process asks, gets — and keep
  no local audit trail.

The gap was consistent: **no tool let me keep fast, autonomous, agentic
engineering while securing the dev machine itself.** And the gap is
widening, not closing: developers debug *production* from their dev
machines all the time — prod SQL creds, SSH keys, service tokens pulled
down to where the debugger runs — and AI-assisted debugging multiplies
how often that happens and how many processes are present when it does.
Trusted tooling on the dev box is the precondition for that workflow to
be safe at all. That's the tool I couldn't find, so it's the tool byn
is. The full strengths-and-weaknesses comparison — byn's own weaknesses
included — is in [byn vs the other tools, honestly](tool-comparison.md).

---

## What byn changes about this story

Replay the incident with the credentials in byn instead of in
`~/.aws/credentials`:

- **The cheap move finds nothing.** There is no credentials file. The
  vault on disk yields entry *names* and ciphertext; the values are
  AEAD-encrypted and the key lives only in the daemon's memory.
- **Reading a value requires authorization the attacker doesn't
  have.** Value access needs a per-terminal session or fresh
  authentication (NU-3). The attacker's shell — a process I never
  unlocked — gets `auth_required`, not my keys.
- **Using the credentials requires an *approved command*.** With a
  trusted `.byn` and a pinned `[exec] actions` list, only the exact
  commands I authorized run without fresh proof-of-presence. "Whatever
  command the attacker types, with my creds injected" is not in that
  list.
- **And the attempt is loud.** Every value access and every exec
  attempt — including denials — lands in the HMAC-chained audit log.
  Instead of discovering the takeover from AWS-side damage, the trail
  starts at the first probe *on my box*: what was tried, when, from
  which caller. Detection moves from "after the consequences" to
  "at the attempt."

Meanwhile the agents keep their speed: pinned actions run free, the
`.byn` manifest declares what each project may do, and I authorize new
actions once instead of babysitting every run. That's the actual
resolution of the IAM tension — **authorization on the dev box, per
command, instead of permission-starving the cloud role the agents
depend on.**

---

## Honest limits — what byn would *not* have fixed

- If the attacker had gotten **root** on the VM, or had obtained my
  **master password**, byn's model is explicit that this is game over
  for any user-space tool ([Security model](../security.md)).
- An attacker patient enough to squat inside a terminal holding a
  **live session** could use that session until it expired or was
  locked — per-terminal sessions narrow this drastically, but the
  same-UID ceiling is real with privilege separation off (the default).
  Privsep shipped opt-in in v0.3.0 (`[security] privsep` + `sudo byn
  setup`) raises that bar to root.
- The on-box audit trail of a fully compromised machine can be tampered
  with by an attacker holding the vault file; **off-box anchoring** of
  the chain head is planned to close exactly that.
- And least-privilege IAM is still worth doing. byn is a layer, not a
  replacement for cloud-side hygiene — short-lived, scoped credentials
  (a planned byn broker integration) are where the two layers meet.

---

## The lesson I actually took

The failure wasn't exotic. It was the **default posture of every dev
machine**: durable credentials, plaintext, well-known path, zero
read-detection — on a box increasingly operated by software I don't
watch. Fixing that posture without giving up agent-speed development is
byn's job description.

For the general version of this analysis, read
[How agents leak secrets](how-agents-leak-secrets.md); for the
industry-wide incidents that rhyme with this one, see
[Real-world incidents](real-world-incidents.md).
