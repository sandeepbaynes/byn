# Quickstart — 5 minutes

Get byn running and store your first secret. byn keeps credentials encrypted in
a local per-user daemon and injects them into commands on demand — values never
touch your shell history, `argv`, or scrollback, and are never written to disk in
plaintext.

---

## 1. Install

```sh
# Homebrew (macOS/Linux) or the install script — both put `byn` on your PATH:
brew install sandeepbaynes/tap/byn
# or
curl -fsSL https://raw.githubusercontent.com/sandeepbaynes/byn/main/install.sh | sh
# or, with the Go toolchain (builds from source). `go install` takes one binary
# at a time, so byn's two helpers come separately — or let byn fetch the editor
# itself the first time you run `byn edit`:
GOBIN=$HOME/.local/bin go install github.com/sandeepbaynes/byn/cmd/byn@latest
GOBIN=$HOME/.local/bin go install github.com/sandeepbaynes/byn/cmd/byn-exec-helper@latest
sudo "$(command -v byn)" setup
```

**Homebrew, the install script and the system packages bundle everything.** byn
ships three binaries — `byn`, the privileged spawn helper, and the editor
`byn edit` runs — and every packaged install places all of them. There is no
separate thing to install.

Only `go install` is different, because it installs one main package per
invocation. The spawn helper is listed above because privilege separation needs
it at setup time; the editor is not, because the first `byn edit` offers to
fetch it, pinned to your byn's own version, and asks before doing so.

> **The install script and the packages provision for you.** They run
> `byn setup` as part of installing, which is why they ask for your password:
> privilege separation is what keeps an exec child's secrets out of your own
> `ps`, and it needs root once. A `go install` cannot do this — the Go toolchain
> runs no install hook — so it is the one path with a manual step.

> **Why GOBIN.** Plain `go install` drops the binary in `~/go/bin`, which is on
> no default PATH and outside sudo's `secure_path`, so `byn` is not a command
> you can run and neither is `sudo byn`. Pointing GOBIN at a directory already
> on your PATH avoids that; `sudo byn setup` also links byn into
> `/usr/local/bin` once it can.

> **Why two binaries.** `byn setup` installs the privileged spawn helper from
> **beside the byn binary**, so a `go install` of `cmd/byn` alone cannot
> provision privilege separation — setup will not find the helper. Homebrew,
> the install script and the system packages ship both.

> **`go install` does not put byn on your PATH.** It installs to
> `$(go env GOPATH)/bin` (usually `~/go/bin`); if `byn` is not found straight
> after installing, that directory is missing from your PATH — add
> `export PATH="$HOME/go/bin:$PATH"` to your shell rc. Homebrew and the install
> script handle this for you.

> **Why `sudo "$(command -v byn)" setup` and not `sudo byn setup`.** sudo
> resolves commands against `secure_path` — typically `/usr/local/sbin`,
> `/usr/local/bin`, `/usr/sbin`, `/usr/bin` — and never your own PATH. The
> install script and the system packages put `byn` in one of those, so plain
> `sudo byn setup` works for them. Homebrew on Apple Silicon
> (`/opt/homebrew/bin`) and `go install` (`~/go/bin`, or the `GOBIN` above) are
> outside it.
>
> "Command not found" is the harmless outcome. The one to avoid is an OLDER byn
> already sitting in `/usr/local/bin`: sudo finds that one, it provisions
> happily using its own helper, and reports success — so you upgrade, run setup,
> and are told everything worked while the new byn was never involved. Naming
> the path removes the guess. `byn doctor` reports the same disagreement after
> the fact.

---

## 2. Start the daemon

All of byn's logic lives in a background daemon that holds the vault key in
memory; the CLI is a thin client over a Unix socket.

```sh
byn start                   # detached
# …or have it auto-start on login (launchd on macOS, systemd --user on Linux):
byn daemon install
```

---

## 3. Create and unlock the vault

```sh
byn init                    # creates the vault and sets your master password
byn unlock                  # unlocks it for this terminal
byn status                  # confirm: daemon up, vault unlocked
```

Each terminal window gets its own session — `byn unlock` in one terminal does
not unlock for other terminals or background scripts. Run `byn unlock` once per
terminal. Use `byn lock --session` to revoke just this terminal's access without
affecting other open sessions.

> **Before you store real secrets — three things byn depends on:**
> 1. **Pick a long, high-entropy master passphrase.** The vault file is portable
>    by design, so a stolen copy is only as safe as that passphrase.
> 2. **Turn on host full-disk encryption** (FileVault / LUKS) — it protects the
>    vault file *and* the entry names/metadata, which are plaintext at rest.
> 3. **Run AI agents and untrusted tooling under a separate OS user or VM, not
>    your primary account** — by default, code running as your UID can reach an
>    unlocked vault.
>
> The full, honest list is in
> [Known weaknesses & how to protect yourself](security.md#known-weaknesses--how-to-protect-yourself)
> and the [Best practices](security.md#best-practices) checklist. Worth two
> minutes before this gets your production credentials.

> **Optional: harden with privilege separation.** byn can run the daemon as a
> dedicated `_byn` service user and run trusted-pinned `byn exec` children as
> `_byn-exec`, so a same-(owner)-UID **non-root** process can't ptrace the daemon
> or read an exec child's injected env. It is **opt-in and off by default** — run
> `sudo byn setup` once, then set `[security] privsep = true` and restart the
> daemon. It raises the bar to root (it does **not** defend against root /
> `CAP_SYS_PTRACE`). See [Migration & setup](migration.md) and the
> [security model](security.md#privilege-separation-the-three-uid-model-opt-in-nu-56).

---

## 4. Store your first secret

`byn put` asks for the value and hides what you type, so it never lands in your
shell history:

```sh
byn put DATABASE_URL
# Value for DATABASE_URL (hidden):
byn list                    # → DATABASE_URL
```

For a value already on disk, or a multi-line one, pipe or redirect it instead —
only the filename reaches your history:

```sh
byn put TLS_KEY < server.key
printf 'postgres://user:pass@localhost/app' | byn put DATABASE_URL
```

What byn will not accept is `byn put NAME value`: an argument is visible in `ps`
to every process on the machine while the command runs, and it is written to your
shell history file.

---

## 5. Use it

Inject scoped secrets into any command — the child process sees them as
env-vars; you never see the value:

```sh
byn exec -- your-app                 # runs your-app with DATABASE_URL in its env
byn exec -- printenv DATABASE_URL    # prove it's there
```

Or read one explicitly:

```sh
byn get DATABASE_URL
```

---

## 6. The web portal

```sh
byn web                     # opens the local admin portal in your browser
```

Store, reveal, rename, import/export, and browse the tamper-evident audit log
visually. From the portal you can also **enroll a passkey / Touch ID** for
password-free unlock, and use the **`.byn`** button to open the `.byn studio` —
an assisted authoring environment for project scope files: structured builder
form, inline TOML validator, command-tester (simulate the exec gate before
trusting), and one-click save+trust. See [portal.md](portal.md) for the full
panel reference.

---

## Next steps

- **Per-project scope:** drop a `.byn` in a project root (or generate it from the
  portal) so `byn` auto-selects the right vault/project/env there — and
  `[exec] env` controls exactly which vars `byn exec` injects. Use
  `[exec] actions` to pin the specific commands that run without per-call
  authorization (the secure default requires it):

  ```toml
  [scope]
  project = "myapp"

  [exec]
  env     = ["DATABASE_URL", "AWS_ACCESS_KEY_ID"]
  actions = ["/usr/bin/env", "/usr/local/bin/your-app"]
  ```

  Approve the file once with `byn trust ./.byn`, then `byn exec` injects
  env-vars password-free for the listed commands. See
  [byn-file-format.md](byn-file-format.md).
- **Organize:** secrets live at **vault → project → env** —
  `byn project create`, `byn env create`. Full command list in the
  [README](../README.md#commands).
- **Daily driver:** run `byn` with no arguments for the TUI, and `byn doctor` to
  self-check the daemon, vault, schema, and audit chain.

Your secret *values* are encrypted at rest and never written to disk in
plaintext, never exposed to your shell, and never handed to agents that don't
go through byn. (Entry *names* and metadata are plaintext at rest, and — unless
you enable privilege separation — code running as your own UID can still reach
an unlocked vault. Even with privsep on, root / `CAP_SYS_PTRACE` remains the
ceiling. See [Known weaknesses](security.md#known-weaknesses--how-to-protect-yourself).)
