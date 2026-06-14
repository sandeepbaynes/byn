# byn + VS Code

Inject vault env-vars into the process VS Code launches without
plaintext leaking into `launch.json`, the terminal, or scrollback.

---

## Prerequisites

- `byn` on `$PATH`
- Daemon running: `byn daemon start`
- Vault unlocked: `byn unlock`
- The vault has the env-vars you need: `echo s3cr3t | byn put DB_URL`

---

## Approach 1: launch.json (debug)

Use `byn exec` as the wrapped command. The debugger attaches to the
spawned process, which inherits the injected env vars.

### Node.js / TypeScript

```jsonc
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Node — via byn",
      "type": "node",
      "request": "launch",
      "runtimeExecutable": "byn",
      "runtimeArgs": ["exec", "--", "node"],
      "program": "${workspaceFolder}/src/index.js",
      "console": "integratedTerminal"
    }
  ]
}
```

### Python

```jsonc
{
  "name": "Python — via byn",
  "type": "debugpy",
  "request": "launch",
  "python": "byn",
  "pythonArgs": ["exec", "--"],
  "program": "${workspaceFolder}/app.py",
  "console": "integratedTerminal"
}
```

Some Python extensions reject a non-Python `python` field. If so, use
the `args` field with a python interpreter directly:

```jsonc
{
  "name": "Python — via byn (alt)",
  "type": "debugpy",
  "request": "launch",
  "module": "your_app",
  "console": "integratedTerminal",
  "preLaunchTask": "byn-exec-prep"
}
```

…and define a task that exports the env (`byn exec` doesn't work
for inline debugger attach in all extensions; see Approach 2 for the
universal fallback).

### Go

```jsonc
{
  "name": "Go — via byn",
  "type": "go",
  "request": "launch",
  "mode": "exec",
  "program": "byn",
  "args": ["exec", "--", "${workspaceFolder}/bin/myapp"],
  "console": "integratedTerminal"
}
```

For `mode: "debug"` (delve attaches by source), Go's launch.json runs
`go build` itself — `byn exec` doesn't fit there. Use Approach 2.

---

## Approach 2: tasks.json (universal)

Generic launcher that works for any language without quirks. Define a
task that runs `byn exec`, then bind it to a keyboard shortcut.

```jsonc
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "byn: run current entry",
      "type": "shell",
      "command": "byn",
      "args": ["exec", "--", "${input:cmd}"],
      "presentation": { "reveal": "always", "panel": "dedicated" },
      "problemMatcher": []
    }
  ],
  "inputs": [
    { "id": "cmd", "type": "promptString", "description": "Command to run" }
  ]
}
```

---

## Approach 3: integrated terminal

Open a VS Code integrated terminal and run:

```
byn exec -- npm run dev
byn exec -- python app.py
byn exec -- ./bin/server
```

Values appear in the child process; nothing is written to history or
shell variables.

---

## Per-project scope

Pin a project + env to the workspace so `byn exec` uses the right
secrets without flags:

`.vscode/settings.json`:
```jsonc
{
  "terminal.integrated.env.linux": {
    "BYN_PROJECT": "${workspaceFolderBasename}",
    "BYN_ENV": "dev"
  },
  "terminal.integrated.env.osx": {
    "BYN_PROJECT": "${workspaceFolderBasename}",
    "BYN_ENV": "dev"
  }
}
```

Then `byn exec -- ...` inside the terminal scopes to that project
and env automatically.

---

## Gotchas

- The values are injected into the **child** process. They do **not**
  appear in your interactive shell. This is intentional.
- `byn exec` requires `--` before the child command. Without it,
  flags meant for the child are eaten by `byn`.
- The daemon must be running and the vault unlocked. The CLI prints a
  clear error and exit code 2 (daemon down) or 3 (vault locked) so the
  IDE shows them inline.
