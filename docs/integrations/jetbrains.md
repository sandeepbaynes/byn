# byn + JetBrains IDEs (IntelliJ, GoLand, PyCharm, WebStorm, …)

Inject vault env-vars into Run/Debug configurations without typing
plaintext into the IDE's "Environment variables" field (which gets
saved into `workspace.xml` and accidentally committed).

---

## Prerequisites

- `byn` on `$PATH` and resolvable from the IDE's launcher
  environment. On macOS, IDEA Launcher inherits a stripped PATH —
  if `byn` isn't found, run the IDE from a terminal once, or set
  `Path Variables` (Settings → Appearance & Behavior → Path Variables)
  to include the directory containing `byn`.
- Daemon running, vault unlocked.

---

## Approach 1: wrap the interpreter / executable

Most Run configurations let you change the **interpreter** or
**runner** path. Set it to `byn` with `exec --` as the prefix.

### IntelliJ — JVM-based run config

Run config doesn't let you replace `java` directly. Use **External
Tools** instead (see Approach 2) or wrap your run script.

### GoLand — Go build / run

Use a **Shell Script** run configuration with:

- **Script path**: `byn`
- **Script options**: `exec -- go run ${FilePathRelativeToProjectRoot}`
- **Working directory**: `$PROJECT_DIR$`

For debug, use a **Go Build** configuration and override the binary
path to a script that calls `byn exec -- ./bin/myapp`.

### PyCharm — Python script

- **Interpreter**: `/usr/local/bin/byn` (full path required by
  PyCharm)
- **Interpreter options**: `exec -- python`
- **Script path**: as normal

### WebStorm — Node.js

Similarly: set **Node interpreter** to `byn` and **Node parameters**
to `exec -- node`.

---

## Approach 2: External Tools

`Settings → Tools → External Tools → +`:

- **Name**: Run via byn
- **Program**: `byn`
- **Arguments**: `exec -- $Prompt$`
- **Working directory**: `$ProjectFileDir$`

Bind a shortcut to it (`Keymap → External Tools → Run via byn`).
Triggering it opens a prompt for the command, then runs it with vault
env-vars injected.

---

## Approach 3: terminal

The simplest: `Alt+F12` (or **View → Tool Windows → Terminal**), then:

```
byn exec -- npm test
byn exec -- ./gradlew bootRun
```

---

## Per-project scope

`File → Settings → Tools → Terminal → Environment variables`:

```
BYN_PROJECT=my-app
BYN_ENV=dev
```

Now the terminal scope is pinned, and so is anything you launch from
the IDE's terminal.

---

## Storing env vars in the run config — DON'T

Avoid pasting secrets into the "Environment variables" field of a Run
configuration. JetBrains stores them in `.idea/workspace.xml`. That
file is local-by-default but easy to commit by accident. `byn exec`
keeps secrets out of every file the IDE touches.
