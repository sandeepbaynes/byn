# Changelog

Notable changes per release. The GitHub release page carries the full commit
list; this file carries what you need to know before upgrading.

## v0.5.0 — unreleased

byn stops needing a person in the middle of an agent's work.

The theme is one sentence: an agent should be able to create a secret, use it,
and keep working, without a human at a terminal — and without the vault being
left open, which is what "just unlock it first" really means.

### Upgrading

Two steps beyond replacing the binary. Both fail closed, so nothing breaks if
you skip them; features stay dormant instead.

1. **`sudo byn setup`** (privsep installs). The systemd unit changed. It had
   `ProtectProc=invisible`, which hid every process owned by you from the
   daemon — so the audit log recorded no caller name for anything done over the
   socket, and the daemon could not tell which agent stored a value. Both failed
   silently. `byn doctor` now reports `daemon.sees_caller`.
2. **Re-trust each project** (`byn trust`, or whatever your repo wraps it in) if
   you want `byn put` to work on a *locked* vault there straight away. Grants
   made by an older byn carry no key it may write with, and only the locked path
   needs one — creating a value on an unlocked vault was never gated and still
   is not. Grants made by this release carry it from the start.

   You can also do nothing. Storing any value in that scope with the vault open
   re-seals the grant, including an ordinary put of your own — so routine use
   heals it. Either way it is logged as `trust.authored_key`.

If you read the audit log with a program, two events changed shape: a write with
no credential behind it is logged as `put.unattended` rather than `put`, and
raising an approval is `pending` rather than `denied` — nothing was refused by
asking, and the two were indistinguishable before.

The vault schema moves to v5. It migrates on open, adds columns, and rewrites no
secrets: existing entries keep the scheme they were written under and stay
readable indefinitely.

### An agent can now work alone

- **`byn put` no longer needs an unlocked vault.** A scope has a second key,
  derived from the vault key and sealed into a trusted `.byn`'s capability under
  the machine key, so a locked daemon can store what a caller creates and give
  it back. It opens nothing that was already there. The honest cost: a value
  stored this way is protected by that machine as well as by your master
  password — which is strictly less exposure than leaving the whole vault open.
- **A caller may read and replace the values it created**, without a credential,
  for as long as its session lives and nobody else has written them. A new
  terminal, a restarted agent, or someone else overwriting it all end that, and
  the ordinary rules resume. See `byn help unattended`.
- **Adding such a variable to `[exec] env` needs no approval.** Being asked
  permission to read back a value you supplied protects nothing.
- **A caller may delete a value it stored**, as long as nobody else has written
  it since — another writer takes it out of your hands at that moment. Whatever
  an agent can put into a program's environment, it can take back out; without
  that it could plant and not unplant. The create, any change and the removal
  are all in the audit log with a name, a time and a caller.
- **A command the `.byn` does not pin raises a decision** — an id and exit 75 —
  instead of dead-ending at a password prompt no agent can answer. Approving it
  actually grants it; a refusal is a wall carrying the reason, and `--force-ask`
  is how you ask again.

### Knowing what will happen, and what did

- `byn exec --dry-run` answers "would this run, and do its variables have
  values?" in one call that runs nothing and queues nothing.
- `byn exec --json` reports a paused or refused command as data, so an id no
  longer has to be scraped out of an English sentence.
- `byn exec --wait-approval[=DUR]` blocks for a decision instead of exiting.
- A variable a `.byn` declares with no value is named at launch, instead of the
  program starting fine and dying at first use.
- `[exec] optional` marks variables the program can run without, so the check
  stops firing on a healthy machine.
- `byn ps` shows which project each child belongs to; `byn approve --history`
  shows what was decided.

### Approval cards say who asked, and what for

A card used to read "runs make dev" and stop there. The owner could see what
was asked and had no way to tell which agent asked it, or why — so answering
meant going and asking, which is the interruption the queue exists to remove.

Cards now carry both, and keep them apart. **Who** is read from the kernel: the
agent byn holds responsible (the same identity that governs values an agent
created), its working directory, and whether anyone was at a terminal. **Why**
is the asker's own sentence, passed as `byn exec --reason "…"`, shown as the
unverified claim it is. byn does not check it and never lets it affect a
decision. A retry that carries a reason fills in a blank one on the same pending
request, and never overwrites one already there.

Both surfaces also now say what approving does: it authorizes, it runs nothing,
and it does not edit the `.byn`. That was the first question people asked of
these cards.

### A command grant belongs to whoever asked for it

Approving an unpinned command used to grant it to the project: anything running
in that directory could run the same string for the next six hours. The owner
was asked whether one agent could run one command, and byn was reading the
answer as "anyone here may".

Grants are now bound to the caller that asked, using the same identity that
governs values an agent created. `byn approve <id> --anyone` widens one
deliberately — a shared build command, or one that has to outlive the session
that asked — and both the list and the approval line say which a grant is.

Grants made before byn recorded who was asking stay usable by anyone. Re-asking
for every existing grant after an upgrade is how people learn to approve without
reading.

### Requests say when they are needed, grants say how long they last

A caller waiting on a decision (`byn exec --wait-approval`) now records how long
it will wait, so the list can separate "needed within 1m20s" from "no longer
waiting" — two rows that looked identical before, one with a process sitting on
it and one abandoned. Answering after that still grants; the entry is marked as
having arrived late, and nothing runs by itself.

`byn approve --for 30m` sets how long an approved command runs free, instead of
the default six hours for everything (24h ceiling). A command wanted once for the
next ten minutes should not become a standing authority.

`--why` is accepted as a spelling of `--reason`, and `BYN_WHY` in the
environment does the same for harnesses that build byn's argv themselves.

### `byn runs diff` — the audit question, without the secrets

Asking "has this value been rotated since that run?" had exactly one answer:
`--reveal`, which prints every value the run received. So checking meant putting
live credentials on a terminal, and in one case into a chat window. The warning
fired and was correct; the person went ahead, because it was the only command
that answered the question.

`byn runs diff <id>` answers it and prints nothing. It is a diff in the literal
sense — the digests recorded for the run against what the vault holds now — and
is deliberately not called `verify`, since `byn audit verify` already means the
cryptographic check. Per name: unchanged,
changed since, or deleted since. No credential, and it works while the vault is
locked — the answer comes from comparing a digest of the stored ciphertext,
which needs no key. `--reveal` now points at it at the moment it is being run.

The three wordings are three claims and are not interchangeable. "changed since"
means the entry is still there holding something else. "deleted since" means the
entry that run used is gone — a name deleted and re-created is a new entry, not
a new version of the old one. "could not be read" is about byn, and is not
evidence that anything changed.

### One exit code for a refusal

`byn delete --json` exited 1 on a refusal where every other command exited 3 on
the identical refusal — and 1 is what byn uses for bad usage, so an agent
branching on the code was told its arguments were wrong when it had been refused
authorization. That is the one distinction that decides whether finding a
credential is worth trying. Refusals are exit 3 everywhere now; `--json`
`status` remains the field to branch on, separating "not_found" from
"auth_required".

### Smaller things the field found

- Deleting a name that does not exist says so, instead of asking for a password
  to delete nothing. Absence was never a protected fact here — byn lists the
  names in a scope without a credential.
- A run record marks which of its values byn took in unattended. A value the
  owner provisioned and one an agent invented shape a program identically, and
  the run record is where you go to tell them apart after the launch warning has
  scrolled away. Vault schema v8, additive.
- `byn runs` truncates the command in the list; `runs show` and `--json` keep it
  whole. One `node -e` program was turning a single entry into five lines.
- A run and an approval card now render the same identity the same way. Two
  spellings read as two facts.

### Three defects the live round found

**An authenticated write was silently stored as the agent's.** `byn put
--password-stdin` sent the password only if the write was refused first, so
whenever the unattended path happened to be open the owner's authenticated write
landed under the scope's authored key — machine-protected, and still owned by the
agent whose session created the value, which could go on reading, replacing and
deleting it. Nothing said so. The password now goes with the write. On a locked
vault that ends in "byn unlock, then retry" where it used to appear to succeed,
which is the honest answer: byn cannot seal under a master key it does not hold.

**A locked vault was reported as a rotation.** `byn runs show <id> --reveal`
authorized the action, then failed to open each value because the key was not in
memory, and reported every one as having been replaced since — telling an auditor
that secrets had been rotated when nothing had changed but the lock. A locked
vault is now said once, up front, and "byn could not read this" is reported apart
from "this was replaced".

**A run named its agent by pid alone.** By the time anyone audits, the process is
gone and the number identifies nothing. The name is now recorded when the run
happens (vault schema v7, additive).

### A record of what each run was given

`byn runs` shows every command byn authorised: when, which `.byn` allowed it,
the command, the process and agent behind it, and which values it received.
`byn runs show ID` names them; `--reveal` shows the values, gated exactly as
reading a secret is and recorded as a read.

Runs store references, not copies. Copying would grow without bound and would
turn the trail into an archive of every secret the project has ever had, so a
credential rotated after a leak would stay recoverable — byn does not do that.
Snapshots are stored as differences from the previous one, so a dev server
restarted fifty times costs fifty run records and one snapshot. A value replaced
since a run is named rather than shown: no copy of a superseded secret is kept.

Vault schema v6 adds the three tables this needs. Additive, migrates on open,
rewrites nothing.

### Values an agent invented are never hidden

byn cannot tell a value someone provisioned from one an agent made up, and an
agent can silence a missing-variable warning by inventing one. So it says so:
`put.unattended` in the audit log, a mark in `byn list --long`, a line in
`byn doctor` (including for values no `.byn` declares), and a warning on the
launch line every time one is injected. A project that provisions its secrets by
hand can refuse them outright with `[exec] agent_put = false`, or by name with
`[exec] agent_put_deny` (globs, e.g. `"*_SECRET"`).

### Build artifacts stay yours

Trusting a `.byn` sets a default ACL so anything the exec child creates stays
deletable by you. `byn repair [DIR]` fixes trees built before that. Do not route
`rm` through `byn exec` afterwards: the exec child can only delete what it
created, so a tree you built yourself refuses it.

### Least privilege, kept

An `[exec] env` list is what a project receives — nothing else. A value stored
unattended is subject to that list exactly like any other, so a value one
service's agent invents does not reach another service, and storing a value is
not a way to put a name of your choosing into every process byn runs.

### Fixed

- Approving an unpinned command recorded the decision and applied nothing, so
  the caller was refused again on every retry, forever.
- A refusal consulted whichever decision was found first rather than the most
  recent, so a command denied after being approved raised a fresh request.
- A stale session token — the CLI keeps one on disk and sends it after the
  daemon has restarted — counted as a human being present.
- `byn trust diff` with no argument was an error, contradicting its own help.
- Orphaned `byn exec` children outlived their wrapper.
- `make dist` died on a macOS-only checksum command, and hashed its own
  checksum file.
- byn treated any character device on stdin as a terminal, so a process with
  stdin at `/dev/null` — an agent, a CI job, a cron entry — was offered
  interactive password prompts throughout, and met the refusal one command at a
  time.
- A refusal invited a password before checking whether anyone was there to type
  one, so an unattended caller got two lines addressed to a person ahead of the
  reason it was actually refused.
- `byn get`, `byn put` and `byn delete` report refusals as JSON under `--json`,
  in one shape; `delete` accepts `--json` at all.
