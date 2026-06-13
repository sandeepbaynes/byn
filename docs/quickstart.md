# Quickstart — 5 minutes

Get byn running and store your first secret. byn keeps credentials encrypted in
a local per-user daemon and injects them into commands on demand — values never
touch your shell history, `argv`, or scrollback, and are never written to disk in
plaintext.

## 1. Install

```sh
# Homebrew (macOS/Linux) or the install script — both put `byn` on your PATH:
brew install sandeepbaynes/tap/byn
# or
curl -fsSL https://raw.githubusercontent.com/sandeepbaynes/byn/main/install.sh | sh
# or, with the Go toolchain (builds from source):
go install github.com/sandeepbaynes/byn/cmd/byn@latest
```

## 2. Start the daemon

All of byn's logic lives in a background daemon that holds the vault key in
memory; the CLI is a thin client over a Unix socket.

```sh
byn start                   # detached
# …or have it auto-start on login (launchd on macOS, systemd --user on Linux):
byn daemon install
```

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

## 4. Store your first secret

`byn put` reads the value from **stdin**, so it never lands in your shell
history:

```sh
printf 'postgres://user:pass@localhost/app' | byn put DATABASE_URL
byn list                    # → DATABASE_URL
```

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
