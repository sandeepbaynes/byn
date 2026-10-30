# The trojaned Claude Code extension, and what an editor extension can reach

*Field note · coverage: v0.9.2 · incident: 29 October 2026 · written 30 October 2026*

On 29 October 2026, a tampered build of the Claude Code extension for VS
Code (`Anthropic.claude-code`, version 2.1.313) was served from the Open
VSX registry and, through its mirror, from Cursor's extension
marketplace, for about eleven hours. Anthropic did not build it. When an
editor loaded it, it planted an SSH backdoor, set itself up to survive
reboots, and sent the attacker a summary of the machine, including the
names of any environment variables that looked like credentials.

This note is about that last part, and about what an attacker could do
with the shell the backdoor gives them. Those are the two places a
secrets vault has something to say. The backdoor itself is an endpoint
security problem, and byn does nothing about it.

**The short verdict for byn v0.9.2.** The credential sweep would have
come back empty, because under byn there are no secret values in the
editor's environment to find. An attacker who got a shell through the
backdoor would have found the vault gated and every attempt logged, but
not sealed off; a process running as you is the threat byn narrows, not
one it eliminates. And byn does not protect `~/.ssh` at all, which is
where this backdoor lived.

Verdict key used in these notes: ✓ prevented or defanged · ◐ materially
reduced or detected · ✗ byn would not have helped. Here: ✓ for the sweep,
◐ for the shell, ✗ for SSH and the backdoor.

---

## What happened

The timeline below is assembled from [Cursor's security
notice](https://cursor.com/blog/claude-code-extension-security-notice)
and [StepSecurity's
analysis](https://www.stepsecurity.io/blog/claude-code-extension-trojanized).
Times are UTC.

A clean 2.1.312 was published to Open VSX on 27 October. At about 09:27
on 29 October the trojaned 2.1.313 went live there and, because Cursor's
marketplace mirrors Open VSX, in Cursor as well. Cursor says at most
5,000 of its users received it. At 20:35 Cursor removed the version,
took its whole marketplace offline, audited the rest of its extensions,
rotated keys and rebuilt. A clean 2.1.314 went out at 01:07 on 30
October, and 2.1.313 was purged from the registries. The attacker's
server was taken offline with its hosting provider's cooperation.

How the malicious build got into the Open VSX namespace has not been
made public. Cursor's wording is that the version "was not developed by
Anthropic." The Microsoft VS Code Marketplace is not known to have
served it.

The payload was a loader added to `extension.js`, roughly 7 KB larger
than the clean file. It ran as plain Node.js at module load. Nobody had
to open a Claude conversation, and no package-manager install hook was
involved; starting the editor was enough. According to Cursor, the
loader did four things:

1. It collected the hostname, username, operating system, architecture,
   home directory, environment variable names, working directories, the
   configured Git email, and the public IP address. StepSecurity adds the
   detail that matters for this note: the beacon reported the names of
   environment variables matching `KEY`, `TOKEN`, `SECRET`, `PASS`,
   `AWS` or `GCP`, "revealing which credentials were present." Neither
   write-up says that secret values themselves were sent.
2. It tried to append an attacker-controlled key, with the comment
   `svc-telemetry`, to `~/.ssh/authorized_keys`, to turn on the local SSH
   service, and to open a reverse SSH tunnel to `134.209.82.225`. Cursor
   notes that turning on SSH usually needs admin rights the extension
   did not have, so that step "would generally fail." Adding the key and
   trying the tunnel do not need admin rights.
3. It installed persistence: a LaunchAgent named `com.apple.sysmond` on
   macOS, a scheduled task named `SysMon` on Windows with a Startup
   script as fallback, and a cron `@reboot` entry on Linux. A background
   script retries the tunnel roughly once a minute. Uninstalling the
   extension does not remove any of this.
4. It reported the host details and the state of the backdoor by HTTP
   POST to port 8099 on the attacker's server.

Both vendors give the same advice. If 2.1.313 was installed in that
window, treat the machine as compromised, remove the persistence with
the published scripts, and rotate every credential that machine could
reach, using a different machine to do it.

---

## Why an editor extension is the whole problem

An extension host is a Node.js process running as you. It has your user
ID, your home directory, your environment, and, unlike a browser
extension, nothing between it and your files. That is precisely the
adversary byn's [security
model](../security.md#the-primary-threat-dev-time-ai-agents-reading-secret-files)
is written against: code you did not write, running with your
permissions, on the machine where your credentials live. The [note on
leak vectors](how-agents-leak-secrets.md) calls this vector 5, supply
chain malware wearing your UID. This incident is that vector, with the
twist that the carrier was the editor extension for an AI coding tool
rather than an npm package.

The payload wanted two different things, and byn's answer differs for
each, so it is worth taking them separately.

### The sweep: which credentials are on this machine?

The beacon did not steal values. It listed environment variable names.
On an ordinary developer machine that list is damning on its own.
`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `OPENAI_API_KEY`,
`DATABASE_PASSWORD`: exported in a shell profile, loaded by direnv, or
inherited by the editor from the terminal that launched it. The names
tell an attacker what the follow-up shell is worth before they bother
to connect.

Under byn that list is empty, and the reason is mechanical rather than
clever. `byn exec -- CMD` builds an environment from your current one
plus the vault entries the project's `.byn` allows, and then replaces
its own process with `CMD`. Only that command, and whatever it spawns,
ever holds the values. Your interactive shell never does, so the editor
you launch from it never does, so the extension host never does. The
only byn variables an editor inherits are scope selectors such as
`BYN_PROJECT`, which carry names, not values, and none of them matches
the patterns the beacon was looking for. The honest answer the payload
would have sent home is that there was nothing there.

Two caveats, because byn removes the reason to export secrets, not the
ability. If you still have a literal in `~/.zshrc`, or an `.envrc` that
sets one, the sweep finds it. And a process the extension host can see,
such as a dev server you started with `byn exec` from the integrated
terminal, does hold its injected variables. On Linux a same-UID process
can read that child's `/proc/<pid>/environ` unless privilege separation
is on; with it on, the child runs as the `_byn-exec` user and is marked
undumpable, so the read needs root. On macOS a `ps -E` residual remains,
and the [known
limitations](../security.md#known-limitations-this-release) say so.

### The shell: what happens after the tunnel connects

Assume the worst case. The reverse tunnel came up, and someone has an
interactive SSH session on your machine as you. This is the same-UID
adversary with a terminal, and it is worth walking through what byn
does and does not give them.

They do not inherit your session. byn sessions are bound to the
terminal that created them, so an SSH login is a new terminal with no
session. `byn get PROD_DB_URL` returns `auth_required`, and in `--json`
mode it fails outright instead of prompting. The unlock you did in your
own window this morning grants their window nothing.

If the vault is locked, they are stuck. After the idle timeout, fifteen
minutes by default, or after you run `byn lock`, a read fails hard. A
password alone does not decrypt a locked vault.

Pinned commands still run, and this is the honest edge. A trusted `.byn`
with `[exec] actions = ["make build"]` will run `make build` with its
allowed variables even while the vault is locked. That is the whole
point of autonomous exec, and it cuts both ways: an attacker who changes
into that project directory can run the pinned command and read whatever
its output reveals. What they cannot do is add a new command, because
re-trusting the file needs your master password, or approve an ad hoc
`byn exec --var` request, because since v0.9.0 that approval is checked
against the vault's password too. With privilege separation on, the
command's environment is not theirs to read either. Pin narrowly, and
only pin targets whose scripts you control, because a pinned `make` runs
whatever the current Makefile says.

The daemon is the real question. On an unprovisioned machine the daemon
runs as you, and a shell as you can attach a debugger to it while it is
unlocked and lift the vault key, or read a session file out of the data
directory. byn names that ceiling on every page. On a provisioned
machine the daemon runs as `_byn` and exec children as `_byn-exec`, and
reaching either from your user needs root. This payload did not have
root on most hosts; that is the reason Cursor gives for the SSH
enablement step usually failing.

Everything they try is written down. Each denied read, each exec, each
trust failure goes into the vault's HMAC-chained audit log along with the
caller's UID, PID, process name and parent process name. A shell spawned
by `sshd` asking for values at three in the morning looks nothing like
you. `byn audit tail` over the exposure window is the first thing to
read.

Finally, the file. With file access as you, an attacker can copy
`vault.db` and `wrapped.key`. That copy can be attacked offline against
your master passphrase, and byn is explicit about it in [known
weaknesses](../security.md#known-weaknesses--how-to-protect-yourself).
A long generated passphrase and full-disk encryption are the controls.
Argon2id slows a guess; it does not stop one.

### What byn does not touch

The backdoor's mechanism is outside byn entirely: `authorized_keys`, the
LaunchAgent, the cron entry, the SSH service. byn also does not protect
SSH private keys under `~/.ssh`. An `ssh` shim and file gating are on the
roadmap and have not shipped. Treat all of that as an endpoint and
rotation problem.

---

## Would another credential manager have helped?

Partly, and it would be dishonest not to say so. Anything that gets
values out of plaintext dotfiles and shell exports, such as 1Password's
`op run`, Doppler, Infisical, or aws-vault, also empties the environment
sweep. The differences show up in the shell scenario. Those tools'
authorized CLI sessions belong to the user rather than to a terminal, so
an attacker's shell as you inherits them. None has a per-command
pinlist. None writes a per-access audit trail on the developer machine.
The full comparison, including byn's own weaknesses, is in [byn vs the
other tools](tool-comparison.md).

---

## What to do now

If you run Cursor, or installed Claude Code from Open VSX, start with
the check Cursor published:

```sh
grep -qs svc-telemetry ~/.ssh/authorized_keys && echo "svc-telemetry key found"
```

Also look for `~/Library/LaunchAgents/com.apple.sysmond.plist`,
`~/.config/.smt`, `~/.config/.smtk`, and any extension folder named
`anthropic.claude-code-2.1.313-*`.

If 2.1.313 was installed between 09:27 UTC on 29 October and 30 October,
run Cursor's remediation scripts and treat the host as compromised.
Rotate from a different machine.

On the byn side, lock the vault, then read `byn audit tail --lines 500`
for the window and `byn approve --history`, and compare `byn trust list`
with what you expect. If the machine was unprovisioned and the vault was
unlocked at any point during the window, assume the key was readable and
rotate everything in it. If it was provisioned, rotate what the audit
log shows was touched, plus anything a pinned command's output could
have revealed.

Going forward: run `byn doctor`, provision privilege separation if you
have not, keep the idle timeout short, never unlock in the terminal an
agent or an extension's task runner lives in, and pin exact commands
rather than `"*"`.

---

## Sources

- Cursor, [Security notice: malicious version of Anthropic.claude-code (2.1.313)](https://cursor.com/blog/claude-code-extension-security-notice), 29 October 2026.
- StepSecurity, [Trojanized Claude Code Extension Delivered Persistent SSH Backdoor to Developer Machines](https://www.stepsecurity.io/blog/claude-code-extension-trojanized), 29 and 30 October 2026.

*Sources verified 30 October 2026. byn behaviour checked against the
v0.9.2 source and [the security model](../security.md). Reviewed and
re-stamped at each release.*
