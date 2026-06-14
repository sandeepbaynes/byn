# byn + Eclipse / STS

Eclipse Run Configurations have an **Environment** tab that stores
plaintext values into the workspace's `.launch` files. Bypass that and
inject from byn instead.

---

## Prerequisites

- `byn` on `$PATH`
- Daemon running, vault unlocked

---

## Approach 1: External Tools Configuration

`Run → External Tools → External Tools Configurations…`:

- **Location**: `/usr/local/bin/byn` (absolute path)
- **Working Directory**: `${workspace_loc}`
- **Arguments**: `exec -- ${string_prompt:Command:./gradlew bootRun}`

Bind it to a toolbar button for one-click launch.

---

## Approach 2: launch via shell wrapper

Create `scripts/run.sh` in your project:

```bash
#!/usr/bin/env bash
exec byn exec -- "$@"
```

Make it executable: `chmod +x scripts/run.sh`. Then in a Java Run
Configuration, change the **Main class** target to spawn this wrapper
via an external process (use **Run → External Tools** rather than
**Java Application** — Eclipse's Java runner ignores environment
override for inheriting from a wrapper).

---

## Approach 3: Maven / Gradle wrapping

For Maven goals: in **Run Configurations → Maven Build**, set:

- **Goals**: as normal
- Click the **JRE** tab → **VM arguments**: leave empty
- Click **Environment** tab → **Select…** → uncheck "Append" and add
  **just** the env vars you don't keep in byn; the launcher's PATH
  finds `byn`, but you cannot ask Eclipse to wrap `mvn` itself.

Workaround: replace **Goals** with a script that runs:

```
byn exec -- mvn $original_goals
```

…via an External Tool configuration instead of a Maven Build
configuration.

---

## Approach 4: terminal view

The most direct path. Install **TM Terminal** (Help → Eclipse
Marketplace → "TM Terminal"), open a terminal in the project, then:

```
byn exec -- ./gradlew bootRun
byn exec -- ./mvnw spring-boot:run
```

---

## Per-project scope

In External Tools' **Environment** tab, add:

- `BYN_PROJECT` = your project name
- `BYN_ENV` = dev

These are read by `byn exec` to pick the right scope, but they are
NOT secrets themselves, so storing them in `.launch` is fine and gives
you per-project pinning.
