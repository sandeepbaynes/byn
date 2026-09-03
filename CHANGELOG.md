# Changelog

Notable changes per release. The GitHub release page carries the full commit
list; this file carries what you need to know before upgrading.

## v0.6.5 — 2026-09-03

### The v0.6.3 editor left in the bin directory is now actually removed

v0.6.4 said it cleaned this up, and did not. `byn setup` takes an early return
when byn is already in a system bin directory — nothing to relocate — and the
cleanup sat after it. So it ran only on the `go install` path, which is the one
case with no superseded copy, and was skipped on every packaged install, which is
where the leftover actually is.

The test that existed asserted the ordering inside that step, and passed
throughout, because the step was correct. It simply was never reached.

### `sudo byn setup` no longer silently provisions a different byn

sudo resolves commands against `secure_path` and never your own PATH. After
installing to `~/.local/bin`, a plain `sudo byn setup` does not run the byn you
just installed — it runs whatever older copy sits in `/usr/local/bin`, which
provisions happily using its own helper and reports success.

The documented command is now `sudo "$(command -v byn)" setup`, and `byn setup`
says when the machine has several byns reporting different versions, marking the
one about to provision. A warning rather than a refusal: provisioning an older
byn deliberately is legitimate, and staying silent is the only unacceptable
option.

### Setup no longer implies your home directory is finished with

It printed "relocated legacy `~/.byn` → …", which reads as: that directory is
done. It is not. Once provisioned the system root is `_byn`-owned and not
writable by you, so per-terminal unlock sessions go on living in
`~/.byn/sessions/`.

Alongside them sit a `portal.token` and `daemon.log` from before provisioning,
both inert — the daemon re-mints its token in the system root. So the directory
looks like abandoned credentials and is in fact a live session store, and
"relocated legacy" invited exactly the tidy-up that destroys it. `docs/file-layout.md`
now documents this, and the three installed binaries and where each lives.

### The docs called a live security switch vestigial

Four files said `[security] privsep` was vestigial — that it gated only a
server-side path the CLI no longer used, and setting it changed nothing. It is
the switch. `byn exec` asks the daemon whether privsep is on and the daemon
answers from that key, so a machine can be fully provisioned — service users,
spawn helper, ACLs — and still run every exec child at the owner's UID because
the flag is unset.

Telling somebody a security switch does nothing is an invitation to turn it off.
The claim had been identified as wrong and reverted once already, and survived in
README, `features.md`, `cli-reference.md` and a field note; it is now corrected
and held by a test rather than by another careful reading.

### Smaller fixes to the editor split

The launcher compared errors by their message text, reported one failure as two
messages, and took `go install`'s word for where it had written the binary
without checking. The editor also reported daemon failures raw, having lost
byn's own error handling when it moved out — a dead daemon said less than it used
to, for the most common failure there is.

## v0.6.4 — 2026-09-03

### `make install` failed on macOS once byn was provisioned

It refreshes the privileged spawn helper in place, using the Linux form
unconditionally: `install -o root -g root -m 0755` followed by `setcap`. macOS
has no `root` GROUP — it is `wheel` — so the install aborted with
"install: unknown group root", after the CLI had already been replaced. The
build left a machine half-upgraded and returned an error naming a group nobody
asked for.

Had the group been right it would have been worse. macOS has no file
capabilities, so `byn setup` installs that helper **setuid-root at 4755**;
refreshing it at 0755 drops the setuid bit and leaves a helper that can no longer
drop to `_byn-exec`. That is a silent break — privsep exec stops working with
nothing in the output to say why — where the group error at least failed loudly.

Both paths now follow what `byn setup` already knew: 4755 root:wheel on macOS,
0755 plus file capabilities on Linux.

The same asymmetry, quieter, in the line below it: the post-install ownership fix
tested only `/var/lib/byn`, so it was a no-op on macOS, where the system data dir
is `/Library/Application Support/byn`. It now finds the right one and asserts
mode 0711 as well as ownership — on macOS the daemon socket lives inside that
directory, and 0700 is the lockout fixed in v0.6.2.

### The install script threw away the editor binary

v0.6.3 split the TUI into its own `byn-tui`, and `byn edit` resolves it beside
the running `byn` — the same way `byn setup` finds the privsep helper. The
release archive contains it and the Makefile installs it, but `install.sh`
handled only `byn` and `byn-exec-helper`: it unpacked `byn-tui` into a temp
directory and deleted it with the rest. Anyone who installed v0.6.3 with
`curl … | sh` has no editor, and re-running the installer is the fix.

Two smaller drifts around the same binary. `docs/quickstart.md` still told the
Go-toolchain path to install "BOTH binaries" and listed two of three, so that
route also produced an installation without an editor. And `make dist` never
built it, despite its own comment claiming it produces what the installer
downloads — goreleaser, which actually builds the release, has built it all
along.

### A stale release-notes page is now a failing build

The site version is DERIVED from CHANGELOG.md; `docs/releases.md` is written by
hand. That asymmetry produced the same defect twice in two days: v0.6.3 dated its
changelog heading, so every page footered v0.6.3, while the release-notes page
those footers link to stopped at v0.6.2.

`gensite` now refuses to publish a site naming a release its own notes do not
describe, and says which section to add. This is the move `version.go` already
made for the version constant, applied to the page that constant links to — not
deriving the prose, which has to be written, but refusing to ship without it.

### `byn ps` and `byn kill` work on macOS

They were Linux-only, and `kill` failed in the worst way available: it reported
"no byn exec processes found" while children were running, stopped nothing, and
returned success. A command that says it found nothing is indistinguishable from
one that cannot look, so the honest reading of a clean `byn kill --all` was that
there had been nothing to kill.

Linux identifies these processes by walking `/proc`. macOS has no `/proc`, so
the process table is read through `ps` once and classified. Three shapes count:
the `byn exec` wrapper; a process running as the exec service user, an account
that exists for nothing else; and a process carrying `BYN_EXEC_PID` equal to its
own pid, which is the unprovisioned path where `syscall.Exec` replaced byn with
the child so the pid never changed.

One row per job. Under privilege separation that row is the wrapper — the child
beneath it is the same job from the inside, and signalling the wrapper takes the
group. Listing the exec user's processes indiscriminately put a row in `byn ps`
for every iteration of a shell loop over `sleep`, so the output churned every
second; a process whose parent is a listed wrapper, or is itself the exec user,
is inside a job rather than being one. An orphan whose wrapper died IS listed,
because a child still holding injected values is what you came to find.

Killing works because the privileged helper signals the process group. The child
runs as `_byn-exec` and your own shell cannot signal it — which is the same
cross-UID boundary that makes `ps -E` show a privsep child no environment.

The parsing is a pure function tested against real captured `ps` output,
including a right-aligned column layout that positional reading would mis-parse
and a path containing a space that rejoining split fields would corrupt. That
shape of test is the lesson from v0.6.1: a platform file that compiles proves
nothing about what it does.

Also fixed here, and worth mirroring on Linux: summarising `byn exec --vault w
-- npm i` reported the command as `w -- npm i`. Stopping at the first non-flag
token takes the VALUE of a preceding flag for the command. Where an explicit
`--` exists it is the only unambiguous boundary, so it is now looked for first.
The Linux `execCmdSummary` still has the original behaviour, and its own doc
comment already documents the corrected one.

### Upgrading from v0.6.3 cleans up after itself

v0.6.3 installed the editor into the system bin directory. Now that it belongs
in `libexec`, `byn setup` removes the superseded copy — otherwise upgraders keep
one on `PATH` that byn no longer uses and nothing ever updates, frozen at the
version that installed it.

It is removed only after the replacement is in place, so a failure cannot leave
a machine with no editor at all.

### The editor is part of byn, not something to install

v0.6.3 split the editor into `byn-tui` and left it looking like a separate
thing: the install script dropped it, the Go-toolchain path listed a third
command, and it sat on `PATH` as though anyone would run it.

It is byn's helper, so it now lives in byn's own directory —
`/usr/local/libexec/byn-tui`, beside the privileged spawn helper, which has
always been kept there for the same reason. `byn` looks there first, then beside
the running binary, so a source build finds the one it was built with and an
installed byn cannot be shadowed by a stray copy earlier on someone's `PATH`.

Every packaged install bundles it: Homebrew, the curl installer, deb, rpm, apk,
and `make install`. The one path that cannot is `go install`, which installs a
single main package per invocation — so the first `byn edit` now offers to fetch
the editor for you, pinned to your byn's own version rather than `@latest`,
after asking. Fetching and building code from the network is a supply-chain
event, and a secrets manager should not do it quietly.

### `byn edit` no longer replaces the process that ran it

The launcher performs a real `execve`, which is right for a program that owns
the terminal — but it did so before checking there was a terminal at all. A test
that called it on a machine where the editor happened to be installed had its
own test binary replaced mid-run, and the package failed with no failing test
named. It passed everywhere the editor was absent, including where the change
was written.

byn now refuses before exec'ing when there is no terminal, which is also the
better behaviour: replacing this process with one that will immediately refuse
makes the error arrive from a program the user never named.

## v0.6.3 — 2026-09-02

### Every byn command was paying five seconds on some terminals

`bubbletea`'s package init calls `lipgloss.HasDarkBackground()`, which asks the
terminal for its background colour and waits up to five seconds for a reply. It
is unconditional in v1 — the library documents it as a workaround to be removed
in v2, and there is no v2 — so every command in a binary that merely *links*
bubbletea pays it.

Measured on a pty with nothing answering: `byn version` 5.1s, `byn status` 5.1s,
`byn list` 5.1s, against 0.1s for `/bin/true`. It is invisible on a normal
terminal, which answers immediately, and that is why it went unnoticed. It bites
where a controlling terminal does not answer — `script`, serial consoles, CI
runners that allocate a tty, and some agent harnesses.

The editor now ships as its own binary, `byn-tui`, and `byn` no longer links a
TUI framework at all. The same commands now take 0.05 seconds. Go initialises
imported packages before the importing one, so byn cannot pre-empt a
dependency's init from its own code; not linking it is the only way not to run
it.

The rejected alternative was a `replace` directive onto a patched bubbletea —
one line removed, no packaging change. A secrets manager should not carry a
forked dependency to save packaging work.

`byn edit`, `byn view` and `byn` with no arguments are unchanged. The editor is
in the same archive and package, and `byn setup` places it beside `byn` exactly
as it already does for the spawn helper. If it is missing, `byn edit` says so and
names the fix instead of failing with a bare exec error.

The guard is a dependency-graph assertion, not a timing test: a timing test
passes on any developer's machine, because their terminal answers the query.

### `byn put --password-stdin` no longer stores an empty value in silence

With `--password-stdin` the first line of stdin is the password and the
remainder is the value, so `printf 'secret' | byn put NAME --password-stdin`
sends the secret as the password and leaves nothing to store. Where the write
needs no authorization — a new name, the common case for an agent — the daemon
accepted it, byn exited 0, and a later `get` returned `""`. Nothing said the
secret had not been saved.

It is now refused, with a message naming both working forms. An empty value
stored deliberately still works; what is refused is the flag-ordering mistake.
Reported from the macOS test pass, and not macOS-specific.

## v0.6.2 — 2026-09-02

### A relocate could lock you out of your own daemon

`byn setup` creates the macOS system data dir `0711` on purpose: the daemon
socket lives inside it, and you are a different UID than `_byn`, so you need
`o+x` to traverse to the socket. The relocate that runs immediately afterwards
renamed the staged `0700` tree straight over that directory.

The daemon then ran, bound its socket, and answered nobody. Every command
reported "daemon is not running" while `launchctl` reported it up, and `doctor`
agreed with the CLI — so its advice was `sudo byn restart`, which genuinely
succeeded and changed nothing. The one thing that was wrong was the only thing
nothing checked.

The staged `0700` is right for the *contents* — it stops a hostile source
smuggling in a group- or other-readable artifact — and wrong for the *root*,
which is provisioning's to set. The adopt now carries the destination's own mode
across the swap. A destination that did not exist has no mode to carry, so the
private `0700` still stands.

It needed a legacy `~/.byn` to relocate, which means it hit anyone who ran byn
*before* `sudo byn setup` — installing from source and trying `byn start` first
is enough. The documented order (`sudo byn setup` first) avoids it.

`byn doctor` now checks that you can traverse the data dir, and `--repair`
restores `0711` **before** touching the service, then re-probes: both "daemon
running" and "no stale socket" were describing the closed door, so a daemon that
was only unreachable is left running instead of bounced.

### `sudo byn restart` could leave you with no daemon at all

On a machine that was not provisioned, it stopped the daemon and could not put
it back: the stop succeeded, the start was refused because a daemon may not run
as root, and what was left was no daemon and an error about privilege separation
that had never been installed.

`start` had always refused root up front. `restart`, `reload` and `stop` only
ever checked the *non-root* case, so root on an unprovisioned machine passed the
guard. The asymmetry was the bug: the command that takes a daemon down was the
one allowed to get that far. They now refuse before dispatch — and therefore
before anything is stopped — and name both ways out: re-run as yourself, or
`sudo byn setup` if you wanted an `_byn` service to manage. Provisioned
behaviour is unchanged, and `BYN_ALLOW_ROOT=1` still bypasses the guard.

### `ps`, `kill`, `runs` and `repair` reached the documentation

Four commands that shipped without a man page entry now have one, and `ps`,
`kill` and `repair` are in the CLI reference. Both state plainly that `byn ps`
and `byn kill` are **Linux-only today**: on macOS `ps` lists nothing and `kill`
reports "no byn exec processes found" while children are running, stops nothing,
and does not say so in its exit status. Documenting a gap is not fixing it, but
an undocumented gap reads as a working command that found nothing.

## v0.6.1 — 2026-09-02

### The writable-path reconcile did nothing on macOS

It shelled out to `setfacl` unconditionally. macOS has no `setfacl` — it has
`chmod +a`, which byn already uses everywhere else on that platform — so every
invocation failed with "command not found", the error was dropped because the
pass is deliberately best-effort, and the credential lockout the whole thing
exists to fix stayed unfixed.

It compiled, it vetted, it passed every test, and it did nothing. A
cross-compile catches a platform stub that will not build; nothing catches one
that builds and is wrong except asserting what it produces, which there is now a
test for.

The per-file grant is a platform function now: `setfacl -m u:USER:rwX` on Linux,
`chmod +a "USER allow read,write"` on macOS, and no command at all where byn has
no privsep tier — so the caller skips instead of spawning something that cannot
work. No inheritance flags on the macOS ACE: this repairs a file that already
exists and was locked down afterwards, which is the opposite case from the
trust-time grant that sets inheritance on a directory.

Verified on Linux, and now on macOS too. Against a file stripped of its ACL and
chmod'd 0600 — `_byn-exec` genuinely locked out — the next `byn exec` reported
"restored _byn-exec access to 1 tool-state file(s)" and the ACE
`user:_byn-exec allow read,write` appeared on the file. Re-running added no
second entry, confirming `chmod +a` refuses a duplicate rather than
accumulating. `byn request watch` and `byn request cancel` were confirmed on
macOS in the earlier pass.

One cosmetic consequence of the honest limitation below: because the darwin path
cannot cheaply tell "already granted" from "needs granting", it re-issues the
grant and reports "restored ... 1 file(s)" on every run, including runs where
nothing had been locked down. The ACL is correct either way; the count is of
files it re-granted, not of files that needed it.

One honest limitation. On Linux the pass reads the ACL to skip files already
granted, which is what makes running it before every exec affordable. Reading a
macOS ACL means parsing `ls -le` per file, so the darwin path re-issues the
grant instead — `chmod +a` refuses a duplicate ACE rather than accumulating, and
the pass is bounded to the paths a `.byn` explicitly declares, which is a handful
of files.

## v0.6.0 — 2026-09-02

### Shared tool-state files stop locking one identity out

A tool that rewrites its own state file and then chmods it to `0600` — the AWS
CLI does exactly this to its SSO cache — discards whatever ACL it inherited.
Whichever identity wrote last owns a file the other cannot read, and it goes
both ways: refresh a token as yourself and every exec child loses its
credentials with a `CredentialsProviderError`, or let a child refresh it and
your own AWS CLI dies on a `KeyError` it cannot explain. Reported from real use,
where it broke a live service.

No permission scheme survives an explicit chmod, so byn reconciles instead:
before each privsep exec it re-grants `_byn-exec` access to files under the
`.byn`'s declared `[exec] writable` directories that have been locked down since
the last run. It tests the file mode rather than reading each ACL — reading ACLs
entry by entry is what makes a recursive pass cost minutes — and it is silent
unless it repaired something.

It runs as you, which bounds what it can fix: changing a file's ACL requires
being its owner, so this repairs files *you* locked. The mirror case, a file the
exec child locked that you can no longer read, is what `byn repair` is for.

`byn repair` now covers the declared writable directories as well, not just the
project. Reconciling on the way into an exec is enough when a file was locked
between runs, and not enough for a service that is already up: a token refreshed
while a dev server has been running for days leaves that child unable to read it
until something restarts. Repair fixes it in place, without one.

### Trusting a large project no longer takes minutes

`byn trust --recursive` over a monorepo took two to three minutes, and it runs
after every `.byn` edit. The search was never the problem — finding every `.byn`
in a 330,000-entry tree takes 0.39 seconds. The cost was a recursive `setfacl`
over the whole project, once per `.byn` found, measured at 191 seconds on a tree
that size. It is slow because nearly every entry already carries an ACL, so each
one is a real xattr read and rewrite.

That walk only ever needed to run once. A default ACL is inherited at creation,
at any depth, whoever creates the file — so everything added after the first
grant already carries the entry, and only what predates it needs the walk. Trust
now checks whether the project directory already has the inheritable entry, one
`getfacl` on one directory, and skips the walk when it does.

Bulk trust also derives the vault key once for the batch rather than once per
file. Deriving it is Argon2id — deliberately expensive, since it is what stands
between a stolen vault file and its contents — so doing it per file turned a
fixed ~50ms cost into a per-file one. Seventeen projects paid nearly a second
for the same answer seventeen times.

`byn repair` still forces it.

### The fix for that reconcile was doing it to `byn exec`

The writable-path reconcile added the day before was doing the same thing to
`byn exec` that the recursive walk did to trust: 13.6 seconds added to every
exec on a real monorepo, repeating identical work. Two causes, both fixed.

It walked the curated toolchain defaults — `~/.cache`, `~/go`, `~/.config`,
`~/.local` — when the case it exists for is a credential tool rewriting its own
file in a path the `.byn` explicitly declares. That is 21,642 files examined to
serve 18. The exec-time pass now reads only the declared `[exec] writable`
list; the defaults are maintained by an inherited default ACL set once at trust
time, and `byn repair` still sweeps everything.

And it was not idempotent. Work was selected by a mode test, but `setfacl`
answers a 0600 file by setting the ACL mask, which lands in the GROUP bits and
leaves other-read clear — so every file it fixed still matched, and the next
exec granted the same set again. Mode cannot distinguish 0660 from a real group
from 0660 from an ACL mask, so the pass now reads the ACL itself for candidates
the mode test selects.

Measured on the monorepo: 13.591s to 0.016s, and a file whose entry is stripped
by hand is still healed on the next exec, in 27ms.

### `byn approve` is laid out, not written out

`byn approve` is laid out rather than written out. Every field now has a name in
a fixed left column and a value that starts where every other value starts, so
the eye can go down the labels or down the values without the two mixing. The
leading verb of a request ("runs make dev") moves into the label column, which
is what the complaint was: the word introducing a command was the same colour as
the command.

Colours now mean something. They had grown one at a time — `why:` yellow,
`who:` cyan, everything else plain — so two labels of equal importance were
different colours and nothing could be learned from a colour. There are six
roles now (label, ident, warn, bad, good, note), documented, and every colour in
the view comes from one of them. They gate on stdout, so a redirected list is
plain text.

`--history` is a table: dozens of decided requests are rows you scan, not
records you read, and the same layout does not serve both. `--json` still
carries every field untruncated, byte-identical to before.

Also: the per-kind explanation of what approving does is said once for the list
instead of under every card, and durations are one unit for an age ("2d ago",
not "46h9m15s ago") and two for a deadline, where the second unit is the half
hour you were deciding whether you had.

### Agents can be told the outcome of their own request

An asker can now watch its own approval and be told the outcome the moment it
happens, and withdraw a request it no longer needs.

`byn exec` hands back a `watch_ticket` with the `approval_pending` refusal.
`byn request watch <ticket>` blocks until the request is answered and prints the
outcome as JSON — approved, denied, expired, cancelled or revoked, with the
decider's reason and whether the grant is single-use. `byn request cancel
<ticket>` takes the question off the owner's list.

Until now the only way to learn an outcome was to re-run the whole command every
two seconds, which could observe success and nothing else: a poller cannot tell
"denied" from "not yet", and that is the difference between an agent that stops
and one that asks for ever. Decisions are broadcast in-process, so a watch wakes
immediately rather than on a poll interval.

The ticket is the capability, and it is issued exactly once — to the caller that
actually raised the request. A retry, or a second agent asking the same thing,
coalesces onto the existing card and gets no ticket; there is no operation that
returns one for an existing request. That is what stops one agent from acquiring
another's channel by guessing what it would ask for, and then answering for it
or withdrawing its request. byn stores only a SHA-256 of the ticket.

Cancelling is not denying. A denial is the owner's judgment and counts toward
the cooldown that stops a fingerprint being re-asked; a cancellation is the
asker changing its mind, and leaves no mark on the owner's answer history.

### A stale grant no longer reports itself as corruption

A grant that can no longer open a value now says so, instead of reporting
corruption. It used to fail with `wrapped key tampered or corrupted`, which on a
vault holding the only copy of an encryption key reads as "your secret is gone" —
and it sent somebody diagnosing data loss for a condition `byn trust` fixes in a
second.

The cause is inheritance, and it needs no file edit at all. A capability holds
the key that opened a row AT GRANT TIME. A value inherited from the default env
lives in the default env's row; a later `byn put` in the child env creates an
override — a different row, in a different env, under a different key — and the
captured key stops opening it. The AEAD fails, and an AEAD failure looks exactly
like real ciphertext damage. So a plain `byn put` can invalidate a live grant for
exactly one variable, which is why one secret failed while others in the same
env decrypted normally.

byn still fails closed: it cannot re-derive the key without the vault key, and
starting the child without the value would trade a clear error for a failure deep
inside the program. What changed is that it now names the variable, says the
value is intact, and gives the command that fixes it.

### The approve dialog stops describing the wrong decision

The approve dialog no longer claims it re-trusts the file. It said so for every
request — true of a trust widening, false of an unpinned command, where
approving records a grant and touches no file at all. The portal already had
per-kind wording and the dialog was not using it, so it told people the wrong
thing about what they were authorizing.

Its header no longer fights the summary either. "This would grant:" above
"runs /bin/date" is two verbs where one belongs; a request to run something now
reads "Approving lets this run:" with the bare command, and a widening reads
"The .byn asks for:", which composes with details written in their own voice.
The stored summary is untouched — it is what the request fingerprint is computed
from. And a single-use request now says so in the dialog, not only on the card.

### The portal's approvals page was unreachable

The portal's approvals page was unreachable, and had been for its whole life.
Clicking the tab showed an empty page while the badge next to it counted the
requests waiting.

Three pieces each looked right on their own. `locationToRoute` mapped
`/approvals` to the approvals view, `renderContent` knew how to draw that view,
and the renderer drew it correctly. Nothing joined the first to the third:
`renderFromLocation` had no branch for it, so navigating there fell through to
the entries case and rendered an empty scope. The page was not blank — it was
the entries view saying "no env-vars in this scope". The badge and the page were
both telling the truth, about different things.

A test now checks that every view the route parser can produce is one the router
handles. It fails against the old code, which is the only way to know a guard
guards anything.

The approval card also shows the request id now. It renders the .byn path but
never the id — the thing you type at a terminal, and the `approval_id` an agent
just printed — so a card could not be tied back to `byn approve <id>`.

### The TUI can answer approvals

The TUI can answer approvals. `g p` opens the queue: what is waiting, what it
wants to run, whether it asked for a single use, who asked and why. `a` grants,
`o` grants a single use, `d` refuses, `v` takes a grant back, `r` types a reason
that travels with whichever answer follows, and `h` shows what has been decided.

It matters because the queue is where work stops. An agent blocked on consent
stays blocked until a person answers, and until now answering meant leaving the
editor for a terminal or a browser — so the tool already open in front of you was
the one place that could not unblock anything.

Approving asks for the master password, exactly as the terminal and portal do.
Denying and revoking do not: they can only remove authority, and refusing has to
stay the cheaper action or people learn to approve by reflex. The once/always
pair is passed to the daemon rather than resolved in the TUI, so the same gesture
cannot come to mean different things in different surfaces.

### The portal gained the decisions the terminal already had

The portal gained the same decisions the terminal has. It could only approve or
deny plainly: no reason, no single-use, no revoke, and it only ever showed what
was pending.

It now carries a reason on both approve and deny — optional, as at the terminal,
because requiring one would make refusing more work than approving and refusing
has to stay the cheaper action. A request that asked for a single use says so on
the card, and the primary button does what the asker asked for, with the
override next to it labelled by what it does rather than by a flag name. Decided
requests are visible behind a history toggle, with the outcome and the words
that went with it. A live grant can be revoked, which previously meant going to
a terminal.

The rules stay in the daemon and the portal only carries the fields, so a tap in
the browser and `byn approve <id>` cannot come to mean different things.

A request that asked for a single use says so on its own line in `byn approve`,
directly under the command, and is marked `[once]` in the history table. It was
first written into the timing row between the retry count and the vault name —
a list of bookkeeping, which is not what it is: it changes what a plain
`byn approve <id>` does, and an approver should learn that before deciding
rather than from the result.

The decider's `--reason` now reaches the asker, through the watch and nowhere
else. A refusal without a reason leaves an agent guessing between "fix it and
ask again" and "stop". Owners still see it in `byn approve --history`.

### byn asks for the password on the terminal, not on a busy stdin

byn now asks for the master password on the controlling terminal when stdin is
carrying data. `echo "$V" | byn put NAME` used to answer "this action requires
authorization (run `byn unlock` …)" to somebody sitting at a terminal: the value
had arrived on stdin, so stdin was a pipe, so byn concluded nobody was there.
stdin says how data arrived; it does not say whether anybody is present. It now
falls back to /dev/tty, which is what sudo, ssh, git and gpg all do.

The same mistake was in three places — the shared auth retry, `byn exec`, and
the first-run vault offer — so all three are fixed. A machine with no
controlling terminal (cron, a container, CI) still reports the refusal instead
of hanging on a prompt nobody can answer. The lines explaining the prompt travel
to the terminal with it, so redirecting stderr no longer files the explanation
away while a bare "Master password:" waits on screen.

### `byn put` asks for the value instead of refusing to

`byn put NAME` on a terminal now asks for the value and hides what you type,
the way a password prompt does. It used to refuse and explain how to pipe the
value in, which left the obvious thing — type it — as the one option byn would
not take.

Every workaround it suggested is worse than prompting. `echo -n "$VAR" | byn
put NAME` puts the value in shell history, in the argv of a process anyone can
read out of `ps`, and possibly in an audit log. byn already warns about exactly
that when a value arrives as an argument, and then recommended a form with the
same flaw; that recommendation is now the prompt.

The input is hidden for the same reason a password prompt hides it: a terminal
is a shared surface — people behind you, a screen share, scrollback that
outlives the session. The prompt says it is hidden, because an unexplained
silent cursor reads as a hung program.

One line only: a multi-line secret still comes from a file or a pipe, which the
message names. An empty entry is refused rather than stored, since at a prompt
it is almost always a stray Enter — with the deliberate form given, because an
empty value is legitimate.

Piped and redirected input are unchanged, so every script keeps working.

### An asker can ask for a single use

An asker can now request a single-use approval itself: `byn exec --once` (or
`--ask-once`) marks the request, and a plain `byn approve <id>` then authorizes
exactly one run instead of leaving the command live for the rest of the window.

It is the narrowest thing a caller can ask for, and asking narrowly has to be
the easy path or nobody does it. The only party who knows one run is enough is
the one asking — an agent running a one-off script knows it at the moment it
asks; the owner reading a list an hour later does not, and was left choosing
between a wide grant and remembering to revoke.

The request sets a default, never the decision. `--once` on approve still
narrows a request that did not ask; `--always` is the new opposite override,
granting normally despite the ask. An explicit override wins over the request,
and if both are passed the narrower one does — an approver who said both did not
mean to widen. The rule lives in the daemon rather than the CLI, so the portal
and a phone answer the same way a terminal does.

A single-use grant nobody named a window for lapses in 30 minutes rather than
six hours. The two are answers to different questions: an ordinary grant covers
a working session, a one-shot covers a run that is usually already waiting on
it, and six hours of authority for a run that happened in the first minute is
six hours nobody asked for.

The list also wraps to your terminal. An 80-column window is the common case,
and several lines ran to 110 — so the terminal broke them itself, at whatever
character landed on the last column: "the .byn is no / t changed",
"services/ap / i". A wrapped value now continues inside its own column instead
of restarting at the left margin, and `COLUMNS` is honoured so a piped list can
be told the width it will be read at.

### `byn doctor` notices a daemon that is not the installed byn

`byn doctor` now checks that the running daemon IS the installed byn. Installing
byn replaces a file; it does not replace a running process, so until the service
restarts the old daemon keeps serving from the binary it started with — and a
restart that silently did not happen looks exactly like one that did. `byn
status` already said so. Doctor did not: it reported "daemon running (version
…)" and a clean bill of health on a machine whose daemon was two commits behind
the CLI asking. Doctor is the command people run to find out whether an upgrade
landed, so it is the one that has to notice. Repair is called when a tree is known to be wrong,
and the entry on the root proves nothing about what lies beneath it — which is
exactly the situation repair exists to fix.

### The docs site publishes what it renders, and nothing else

The pages workflow copied `docs/` into the built site verbatim, so every
markdown source under it was served raw at its own `.md` URL — including
`docs/design/` and `docs/research/`, which are internal notes that were never
meant to be published.

The site now publishes only the generated pages, which is exactly what
`tools/gensite/site/manifest.go` names. A doc that is not in the manifest is
internal by default. That is the safe direction, and it is enforced rather than
documented: the deploy fails if any markdown source reaches the built site at
all, because the previous rule was also "do not publish the sources" and nothing
checked.

## v0.5.5 — 2026-09-01

### The approval history is readable

`byn approve --history` already kept every request — nothing is ever pruned —
but you could not use it to answer the question it exists for. An expired entry
said only `expired`, with no when, so one that lapsed an hour ago and one from
last week looked identical. A command containing a program (`node -e "…"`) was
printed verbatim, burying every other entry. And the flag was only ever
mentioned when the queue was empty, so an owner whose request had expired was
left with "the agent said it asked for something" and no way to find out what.

Now: expired entries are dated from the moment they lapsed and say when they
were asked, summaries are collapsed to one line in the list (the stored text is
untouched — it is what the fingerprint is computed from), and the pending list
names `--history` whenever there is history behind it. Denials were always
included and now read the same way.

### Single-use grants, and a password that can write

`byn approve --once <id>` makes a grant single-use: spent the first time byn
authorizes a run with it. One-shot scripts are what approvals are most often
used for, and the alternative was remembering to revoke afterwards — a step easy
to skip and invisible when skipped, leaving an arbitrary command runnable for
hours after the job it was approved for had finished. Spent on authorization,
not on the command's exit status, because byn hands over the values and the
command's fate is its own; a dry run consumes nothing.

`byn put` now accepts the master password on a locked vault, as `byn get`
already did. An authenticated write used to be refused outright while an
*unauthenticated* one succeeded — an unattended caller writes under the scope's
authored key, and an authenticated one is meant to seal under the vault key,
which was not in memory. So supplying the password made a write harder rather
than easier, and an owner could not take a value back from an agent without
unlocking the whole vault. The value is sealed under the vault key exactly as it
would be if the vault were open, so it means the same thing: the value is the
owner's, and the agent's claim on the name does not survive it.

### Alias exec is no longer the unprotected form

`byn exec <alias>` ran the child as you, with none of privilege separation's
isolation — so the ergonomic form was the one without protection, and byn said
so on every run rather than fixing it. Authorization was never the obstacle: the
daemon expands an alias and gates the result exactly as it gates a direct
command. The CLI simply could not pin an absolute target before handing one to
the spawn helper, because for an alias it did not know what the target was.

Preflight already answers that, and answers it without side effects — it queues
nothing and spends no grant — so the alias is resolved first and then run
through the ordinary privsep path as the command it actually is. Verified: the
same alias that ran as uid 1000 now runs as `_byn-exec`, and build artifacts are
still removable by their owner.

### A value byn cannot reach is not a value that is missing

A declared variable that the launch did not receive was reported as having no
value — whether it had none, or had one this grant could not open. An
explicit-name capability captures a key per name that has a value when the
`.byn` is trusted, so a name that gains one later is not in it. Being told "no
value" about a value sitting in the vault sends you to set it again; the fix is
to re-trust the `.byn`, and byn now says so.

Nothing changed about which names a grant covers. Widening explicit grants to
derive any value in their scope would have made every capability as broad as a
wildcard one, on a key that is locally computable — a real loss of least
privilege to fix a reporting bug. The common case already heals itself: writing
a value while the vault is open re-seals the grant.

### `byn setup` asks for the password itself

Running it without root used to end at "byn setup must run as root — Run: sudo
byn setup", which is a command you then retype. Worse from a `go install`, where
byn lives outside sudo's `secure_path`: `sudo byn setup` answers `command not
found` for the very command that fixes that.

It now re-runs itself under sudo, so sudo prompts and setup continues. byn
re-executes its own resolved path rather than a name looked up on PATH — the
point is to run *this* byn as root, and a PATH lookup under `secure_path` could
find a different one. It says what it is about to do before the prompt appears:
an unexplained password prompt is alarming, and teaches people to type their
password at whatever asks.

If sudo refuses — not a sudoer, wrong password, cancelled, no terminal to prompt
on — its message stands, since it is the accurate one, and byn adds the command
to run, which sudo cannot know. A guard env var means a sudo that does not
actually elevate produces one honest error rather than an infinite re-exec.

### `byn setup` enables privilege separation, not just provisions it

Provisioning was necessary and not sufficient. `byn exec` asks the daemon
whether privsep is on and the daemon answers from `[security] privsep`, so a
machine could have the service user, the spawn helper and the ACLs all in place
and still run every exec child at the owner's UID — the protection built and
switched off, waiting on a config edit most people never made.

Setup now writes the key and restarts the daemon, which is the moment byn has
both root and your attention. It never overwrites an explicit setting, including
`privsep = false`: turning it off is a decision, and setup is not the place to
overturn it. Re-running is idempotent, which matters because the packages run
setup on every upgrade.

Since v0.5.5 `byn setup` sets `[security] privsep = true` for you and restarts
the daemon, so a normal install ends up separated. It never overwrites an
explicit setting — including `privsep = false`, which is a deliberate choice
setup does not overturn. Without that key exec children run at your UID: the
flag is what `byn exec` asks the daemon about, so provisioning alone does not
isolate anything.

### Documentation corrections

- `spec.md` listed trust-record tampering as undetected with HMAC signing
  "designed" — it shipped: records carry an FPMAC and a VKMAC.
- `spec.md` listed the audit-chain crash window as awaiting a repair mode — it
  shipped: the logger reconciles its head on restart, and `byn audit reseal`
  answers a genuine break.
- `spec.md` listed scope CRUD as deferred everywhere; the portal has it. The TUI
  rail still does not, which is now what it says.
- The CLI reference said `get` and `put` require an unlock while `delete` does
  not. All three now take the master password on a locked vault.
- `byn help lock` said value reads and writes fail until unlock, without
  mentioning the password path, the authored-key path, or that a trusted `.byn`
  still injects.

### Fixed

- **The portal's error toast collapsed to one word per line.** The stack it sits
  in is a zero-width anchor, and an absolutely positioned box shrinks to fit the
  space available in its containing block — which was zero — so the card fell
  back to its longest word. It had a `max-width`, which caps a width but never
  supplies one. It now sets a width and reads as a sentence.
- **`byn setup` was vague about the step still outstanding.** It closed by
  naming `[security] privsep = true` without saying what is true until you set
  it: exec children run at your UID, and anything there can read their injected
  secrets. Provisioning is necessary and not sufficient — `byn exec` asks the
  daemon whether privsep is on, and the daemon answers from that key. Setup now
  says what is not yet protected and points at `byn doctor` for the real state.
- **`install.sh` warns when your shell has a stale byn cached.** Installing byn
  to a new location leaves the calling shell still resolving the old path, so a
  working install reports `No such file or directory`. The script now notices
  and says to run `hash -r`.

## v0.5.4 — 2026-08-31

### Fixed

- **An upgrade could install a byn that never runs, silently.**
  `go install …@latest` with no `GOBIN` puts the binary in `~/go/bin`, which is
  on no default PATH — so an older byn elsewhere kept answering, and
  `byn version` reported the old number immediately after a successful upgrade.
  Nothing was broken and nothing said anything: the install worked, and the
  wrong binary replied. `byn doctor` now lists every byn it can find with the
  version each reports, and fails when they disagree — naming which one PATH
  actually reaches.

## v0.5.3 — 2026-08-31

### Fixed

- **A grant could not be taken back.** Once approved, a command stayed runnable
  until it expired — so a one-shot script approved for a single job sat
  executable for the rest of the window, and an owner who wanted it stopped had
  nothing to run. `byn approve --revoke <id>` takes the grant back. It needs no
  password, for the same reason `--deny` does not: it can only remove
  capability, and a revoke you have to find a credential for is one that happens
  later than it should. Audited as `approval.revoke`.
- **`--deny` on an already-approved request was a silent no-op.** It returned
  the existing record with exit 0 and reprinted the grant line — "approved …
  runs free for 5h53m" — so an owner who typed it to take a grant back believed
  they had, and was wrong about what was still runnable. It is now refused
  outright and names `--revoke`. Repeating the *same* decision stays idempotent:
  two surfaces agreeing is not a conflict.
- **`byn get` asked for the master password, then refused the read.** Supplying
  the password authorized the action, but the value still needed the vault key
  in memory — so byn prompted, accepted the right password, and answered "vault
  is locked". Being asked for a credential, giving the correct one, and being
  refused anyway is indistinguishable from the tool being broken. A password now
  reads the value: the key is unwrapped for that one read and zeroed after, so
  the vault stays locked and it authorizes a value rather than a session.
- **A capability's captured row keys bypassed the `.byn`'s own `[exec] env`
  list.** The loop that injects values from keys captured at grant time
  intersected against `rec.EnvAllowlist()`, which returns nil both for "this is
  a wildcard grant" and for "EnvGrants is empty" — and EnvGrants is not
  persisted, so it is empty on the ordinary call. A nil read as "inject
  everything" let every name captured when the `.byn` was trusted through, past
  the list the file actually declares. This is the same mistake as the
  unattended-value bypass fixed earlier, at a second site; it is narrower, being
  limited to names that already existed at grant time, and identical in kind.
- **One undecryptable value aborted the entire exec.** A captured entry that had
  since been re-sealed under another scheme — an unattended write, typically —
  returned a decryption error that failed the whole call, so a value the `.byn`
  never asked for stopped every value it did ask for from being delivered. Those
  entries are opened by the authored key on another path; the capability loop
  now skips them, and the vault reports the case as a distinct condition rather
  than as prose inside a generic failure.

## v0.5.2 — 2026-08-31

### Fixed

- **A byn installed outside a system directory produced a service that could not
  start.** v0.5.1 linked byn into `/usr/local/bin` with a symlink, and wrote the
  service unit pointing at wherever byn actually lived — which for a `go install`
  is inside the user's home. The daemon runs as the `_byn` service user, which
  cannot read there, so systemd failed at exec with `Permission denied` and the
  service flapped until it gave up: `sudo byn restart` reported success while
  `byn status` still said the daemon was down. byn is now **copied** into
  `/usr/local/bin` before the service is installed, and the unit points at that
  copy — a real file the service user can read. The spawn helper is copied
  alongside it for the same reason. The cost is that a later `go install` needs
  `byn setup` re-run to take effect; the packages already do that on upgrade.
- **Every `sudo byn …` byn suggested was unrunnable from a `go install`.** sudo
  resolves commands against `secure_path`, which never includes `~/go/bin` or
  `~/.local/bin`, so `sudo byn setup` answered `byn: command not found` — and
  the command being recommended was the one that fixes exactly that. byn now
  prints the absolute path when it is not on a path sudo searches.

## v0.5.1 — 2026-08-31

### Installing byn now provisions byn

Privilege separation is what keeps an exec child's secrets out of your own `ps`,
and it needed root once — from a second command, run by whoever remembered.
Every install was therefore half an install, and the missing half was the
isolation.

The system packages (deb/rpm/apk) and `install.sh` now run `byn setup` as part
of installing, while the package manager or the script is already elevated —
which is why installing or upgrading asks for your password. Upgrades re-run it
deliberately: the service unit and the spawn helper change between releases, and
a helper left behind by an older byn is a version-skew bug waiting to happen.
Removing a package tears the service down again and never touches the vault; an
upgrade is told apart from a removal, so it does not stop the daemon mid-upgrade.
Neither one fails the install if provisioning does not work — a machine without
systemd is a normal reason to land there, byn still runs, and `byn doctor` says
what is missing.

`byn setup` also links byn into `/usr/local/bin` when it was installed somewhere
only your own shell can see. `go install` puts binaries in `~/go/bin`, which is
on no default PATH and outside sudo's `secure_path` — so the install produced a
working binary that could not be run as `byn`, and could not be reached by
`sudo byn` either. A symlink rather than a copy, so a later `go install` is
picked up without re-running setup.

The Go toolchain runs no install hook, so a `go install` cannot provision or
place itself; it is the one path with a manual step, and the docs now say so and
show how to install straight onto your PATH with `GOBIN`.

### Fixed

- **byn could not be started on a machine it had been uninstalled from.**
  Whether privilege separation was provisioned was judged by whether the `_byn`
  accounts existed — and `byn uninstall` deliberately keeps those while removing
  the service, the helper and the owner record. So byn declared such a machine
  provisioned, refused to start a daemon as you, and sent you to
  `sudo byn restart` for a systemd unit that had been removed: a dead end with
  no way out of it from the CLI, reachable by following the documented uninstall.
  Provisioning is now judged by what setup actually installed, and the three
  states are told apart — nothing installed (`byn start`), service installed
  (`sudo byn restart`), and a data directory with no service to serve it
  (`sudo byn setup`, which is the one that was unreachable).
- **`go install` produced a binary that reported version 0.0.1.** The version is
  stamped by the linker at release time, and `go install` applies none of those
  flags — so a correctly installed v0.5.0 called itself by the placeholder that
  a plain `go build` starts from. Go embeds the module version in the binary
  itself, so when nothing was stamped byn now asks the binary: an install from
  the module proxy reports its real version, and a build from a working tree
  reports the commit it came from and says when that tree was edited. A stamped
  version always wins, since `git describe` knows things a module version cannot
  express.

## v0.5.0 — 2026-08-31

byn stops needing a person in the middle of an agent's work.

The theme is one sentence: an agent should be able to create a secret, use it,
and keep working, without a human at a terminal — and without the vault being
left open, which is what "just unlock it first" really means.

### Upgrading

Full procedure, rollback and the behavior changes a script may notice:
[docs/upgrading.md](docs/upgrading.md). In short, two steps beyond replacing the
binary. Both fail closed, so nothing breaks if
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

byn writes a verified snapshot of each vault (`vault.db.v<N>.bak`, beside the
vault) before it migrates anything, because upgrading is a one-way door: an
older byn refuses to open a newer vault rather than guess at a format it does
not know. That snapshot is how you go back.

The vault schema moves to v8. Every step migrates on open, only adds tables and
columns, and rewrites no secrets: existing entries keep the scheme they were
written under and stay readable indefinitely. v5 adds the per-entry ordering
columns, v6 the exec-run tables, v7 the agent's name on a run record, v8 which
of a run's values were stored unattended.

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

`byn runs show ID` marks which values byn took in unattended — one an agent
invented and one you provisioned shape a program identically, and this is where
you tell them apart once the launch warning has scrolled away. The list
truncates long commands; `show` and `--json` keep them whole.

**`byn runs diff ID`** answers the question people actually bring here — has any
of this been rotated since? — and prints nothing. Per name: unchanged, changed
since, or deleted since. It needs no credential and works while the vault is
locked, because the answer comes from comparing a digest of the stored
ciphertext, which needs no key.

It exists because the safe command has to be the reachable one. While the only
way to check whether a value had changed was the command that prints every
value, checking meant putting live secrets on a terminal — so `--reveal` now
names `diff` at the moment `--reveal` is being run. It is a diff in the literal
sense, the digests recorded for the run against what the vault holds now, and is
deliberately not called `verify`: `byn audit verify` already means the
cryptographic check.

Its three wordings are three different claims. "changed since" means the entry
is still there holding something else. "deleted since" means the entry that run
used is gone — a name deleted and re-created is a new entry, not a new version
of the old one. "could not be read" is about byn, and is not evidence that
anything changed.

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
- Deleting a name that does not exist asked for authorization instead of saying
  there was nothing to delete, sending a caller to find a credential in order to
  remove nothing. Absence was never a protected fact: byn lists the names in a
  scope without one.
- `byn delete --json` reported a refusal as exit 1, which byn uses everywhere
  else for bad usage, while every other command reported the same refusal as 3.
  A caller branching on the code was told its arguments were wrong when it had
  been refused authorization — the one distinction that decides whether finding
  a credential is worth trying.
