# byn — Documentation

This directory is the reference for users and contributors. Read what
you need; everything cross-links.

> **For contracts** (what must always be true), read
> [`spec.md`](spec.md). It's the single source of truth for
> byn behavior. The files in this directory **explain** that
> behavior — they don't override it.

---

## For users

- **[CLI reference](cli-reference.md)** — every command, flag, env var, and exit code.
- **[`.byn` file + discovery](byn-file-format.md)** — auto-scope from the
  current directory + TOFU trust.
- **[File layout](file-layout.md)** — what the byn data root contains, modes,
  semantics.
- **[Migration & setup](migration.md)** — `byn setup`, `byn migrate` (relocate
  vs import), privilege separation, and the data-root override removal upgrade
  note.
- **[Troubleshooting](troubleshooting.md)** — daemon down, vault locked,
  rate-limited, audit chain broken, etc.
- **[Glossary](glossary.md)** — vault, scope, AAD, TOFU, wrapping, fingerprint,
  audit chain.
- **[Integrations](integrations/)** — VS Code, JetBrains, Eclipse, AI coding agents.

---

## For contributors / curious users

- **[Architecture](architecture.md)** — daemon ↔ CLI IPC, multi-vault state,
  scope hierarchy, SQLite schema, audit log, request flow.
- **[Security model](security.md)** — threat model, crypto primitives,
  key lifecycle, known weaknesses, deferred hardening.

---

## See also

- **[Release notes](releases.md)** — what changed in each release, with
  upgrade / migration notes and specific instructions.
- **`README.md`** (repo root) — quickstart + status.
- **`features.md`** — feature inventory at the last release.
- **`testing.md`** — how the test suite is structured + manual smoke.
- **`man/byn.1`** — install with `make install-man`, read with `man byn`.

---

## Conventions

- A `[scope]` in this doc means `vault → project → env`, the four-level
  hierarchy explained in [Architecture](architecture.md) and the [Glossary](glossary.md).
- "Daemon" means the long-running background process listening on the byn
  daemon socket. "CLI" means the `byn` binary that connects to it.
- File modes are written in octal (`0600` = owner read+write, no group/other).
- On-disk paths are shown relative to the **byn data root**. That root is a
  fixed system path (`/var/lib/byn` on Linux, `/Library/Application Support/byn`
  on macOS) once the machine is provisioned for privilege separation
  (`byn setup`), or the legacy per-user `~/.byn` when unprovisioned (the default).
  See [File layout](file-layout.md). There is no data-root env override.
