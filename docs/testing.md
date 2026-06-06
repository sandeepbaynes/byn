# byn — Testing Guide

How to verify everything works on a fresh checkout, and how to
exercise the features manually.

---

## Automated tests

### Run everything

```sh
make test                  # unit tests with -race
make test-integration      # integration suite (slow — each runs Argon2id)
```

Or directly:

```sh
go test -race ./...
go test -tags=integration ./tests/integration/... -timeout=600s
```

### Coverage

```sh
make cover
open coverage.html
```

### Single test

```sh
go test -race -run TestPutGetRoundtrip ./internal/daemon/...
go test -tags=integration -run TestE2E_Import_Dotenv ./tests/integration/
```

### Lint

```sh
make lint
go vet ./...
```

---

## Manual smoke test (5 minutes)

Builds the binary, exercises the full surface in a throwaway dir.

```sh
make build
export BYN_DIR=/tmp/byn-smoke-$$
mkdir -p "$BYN_DIR"

# 1) Daemon
bin/byn daemon start
bin/byn status                            # → daemon: running

# 2) Init + unlock
echo 'correct-horse-battery-staple' | bin/byn init --password-stdin
echo 'correct-horse-battery-staple' | bin/byn unlock --password-stdin

# 3) Env-var put/get/list
echo 's3cr3t-value'   | bin/byn put MY_KEY
echo 'another-value'  | bin/byn put OTHER_KEY
bin/byn list
bin/byn get MY_KEY
bin/byn list --json

# 4) Exec
bin/byn exec -- /usr/bin/env | grep MY_KEY

# 5) Scope hierarchy
bin/byn project create billing
bin/byn project list
bin/byn --project billing env create prod
bin/byn --project billing env list

# 6) Multi-scope put/get
echo 'billing-secret' | bin/byn --project billing put DB_URL
bin/byn --project billing list
bin/byn --project billing get DB_URL

# 7) Import / export round-trip
cat > /tmp/sample.env <<'EOF'
DATABASE_URL=postgres://localhost:5432/test
API_KEY="value with spaces"
EOF
bin/byn --project billing --env prod import /tmp/sample.env
bin/byn --project billing --env prod list
bin/byn --project billing --env prod export

# 8) Lock / unlock
bin/byn lock
bin/byn get MY_KEY                        # → error: vault is locked
echo 'correct-horse-battery-staple' | bin/byn unlock --password-stdin
bin/byn get MY_KEY                        # → s3cr3t-value

# 9) Shutdown
bin/byn daemon stop
rm -rf "$BYN_DIR"
```

Expected: every command exits 0 except the explicitly-locked `get`,
which returns exit code 3.

---

## Passkey unlock — manual E2E (real hardware)

The WebAuthn PRF unlock path can only be exercised end-to-end against a real
platform authenticator (macOS Touch ID / iCloud Keychain) — a headless-Chrome
*virtual* authenticator does not implement PRF, so it cannot cover the part that
matters. Run on a Mac with **Safari**, or **Chrome with an iCloud-Keychain**
passkey (a Chrome-profile / Google-Password-Manager passkey has no PRF and only
enrolls as session-only):

```bash
make build && bin/byn daemon start && bin/byn web   # portal on http://localhost:2967
```

1. **Enroll.** Unlock the vault, open the **passkey** panel → *Add passkey* →
   choose **iCloud Keychain**, approve both Touch ID prompts (create + PRF
   eval). The new entry must show the green **"unlocks"** badge — grey
   "sign-in only" means PRF didn't fire (wrong authenticator).
2. **Unlock.** Lock the vault, click its unlock action in the sidebar → Touch ID
   → it unlocks **with no password dialog**.
3. **Password still works.** Lock again, cancel the Touch ID prompt → the master
   password dialog appears and unlocks (the password is never removed).
4. **Revoke = lockout.** Revoke the passkey (password-gated). Lock the vault →
   the sidebar no longer offers Touch ID; only the password unlocks.

Must hold: enrollment is refused while the vault is locked; the value is never
recoverable without either the passkey *or* the password; reach the portal at
`http://localhost:<port>` (not `127.0.0.1`, which fails the `rp.id` check).

---

## What the integration suite covers

In `tests/integration/`:

### Lifecycle & basics — `e2e_test.go`
- `TestE2E_GoldenPath` — init/unlock/put/get/list/lock/get-while-locked/re-unlock/delete
- `TestE2E_StatusOnly` — daemon up/down, status output
- `TestE2E_UnknownCommand` — error + help routing
- `TestE2E_VersionStable` — version flag

### `byn exec`
- `TestE2E_Exec_InjectsEnvVars`
- `TestE2E_Exec_RequiresSeparator` (-- before child command)
- `TestE2E_Exec_PropagatesExitCode`
- `TestE2E_Exec_StoredOverridesParent`
- `TestE2E_Exec_HelpReachable`

### Scope flags — `scope_crud_io_test.go`
- `TestE2E_Scope_FlagBeforeSubcommand`
- `TestE2E_Scope_FlagAfterSubcommand`
- `TestE2E_Scope_EnvVarFallback`
- `TestE2E_Scope_DoubleFlagConflictErrors`
- `TestE2E_Scope_DashDashTerminator`

### Vault / project / env CRUD
- `TestE2E_Vault_ListJSON`
- `TestE2E_Vault_DeleteDefaultRefused`
- `TestE2E_Project_CRUD`
- `TestE2E_Env_CRUD`

### Import / export
- `TestE2E_Import_Dotenv` — quoted values with `=`, comments, empty vals
- `TestE2E_Import_JSON`
- `TestE2E_Import_YAML`
- `TestE2E_Import_NestedRejected`
- `TestE2E_Import_Stdin`
- `TestE2E_Export_DotenvRoundtrip` — quoting heuristics
- `TestE2E_Export_JSON`
- `TestE2E_Export_FileOutput` — checks 0600 perms
- `TestE2E_ImportExport_Roundtrip`

---

## What is NOT yet covered by tests

- TUI integration against a real daemon (the new bubbletea TUI has
  per-tier snapshot + render tests; full end-to-end against a live
  daemon needs a fake-TTY harness, deferred).
- macOS Secure Enclave wrapping (`hwkey/macos.go`) — gated on
  entitlements; tests skip without them.
- `byn history` / `revert` / `diff` — entry-version CLI not yet
  shipped (schema + `entry_versions` table are in place).
- IDE integration recipes — documented but not auto-verified.
- WebAuthn PRF cold-unlock — covered at the Go layer (passkey package, daemon
  ceremony ops + adversarial/one-time/revoke-lockout tests, portal handler
  tests) and validated end-to-end manually on real hardware (above). An
  automated headless-Chrome *virtual-authenticator* harness is deferred: CDP
  virtual authenticators don't implement the PRF extension, so they can't
  exercise the cold-unlock path.

---

## Reporting regressions

If a test breaks:

1. Run `go vet ./...` and `make lint` first; lints often shake out
   the cause.
2. Run the single failing test with `-v -race` to surface goroutine
   issues.
3. Check whether `BYN_DIR` was set; integration tests use
   per-test short dirs to dodge the macOS 104-char `sun_path` limit.
4. Check daemon logs at `$BYN_DIR/daemon.log` — the detached
   daemon writes its stdout/stderr there.
