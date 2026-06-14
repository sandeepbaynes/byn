# byn integrations

How to make byn play with your editor, debugger, and agent.

For the rest of the docs, see [`../`](../).

---

## TL;DR

`byn exec -- COMMAND ARGS` is the universal way to inject vault
env-vars into anything. The integration docs in this directory just
explain how to invoke that wrapper through each IDE's launcher.

Most installs also want a per-project `.byn` file so the IDE's
shell/tasks automatically pick up the right scope — see the
[`.byn` file format](../byn-file-format.md) doc.

- [VS Code](vscode.md) — `launch.json`, tasks, integrated terminal
- [JetBrains IDEs](jetbrains.md) — IntelliJ, GoLand, PyCharm, WebStorm
- [Eclipse / STS](eclipse.md) — External Tools + shell wrappers
- [AI coding agents](ai-agents.md) — agent-safe usage patterns

---

## What's in scope per IDE

| IDE       | Launch.json/run config | Terminal | Pre-launch task |
|-----------|------------------------|----------|-----------------|
| VS Code   | yes (Node, Python, Go) | yes      | yes             |
| JetBrains | partial (script-based) | yes      | yes (External Tools) |
| Eclipse   | via External Tools     | yes (TM Terminal addon) | yes |

---

## Common pitfalls

1. **Daemon not running.** Run `byn daemon start` once per login.
   The IDE will get exit code 2 and a clear message.
2. **Vault locked.** Run `byn unlock`. Exit code 3 surfaces in the
   IDE.
3. **`byn` not on PATH inside the IDE.** macOS launchers strip PATH.
   Launch the IDE from a terminal once, or put `byn` somewhere the
   IDE finds (e.g., `/usr/local/bin`).
4. **`--` missing.** `byn exec` requires `--` before the child
   command to separate its own flags from the child's. Without it the
   wrapper consumes flags meant for your app.
