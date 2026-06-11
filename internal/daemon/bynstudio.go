package daemon

// bynstudio.go implements the portal .byn studio daemon ops:
//
//   - byn.validate  — validate .byn content (errors + warnings)
//   - byn.simulate  — simulate exec verdict for a command line against content
//   - byn.read      — read a .byn file with its current trust status
//   - config.get    — read raw config file bytes
//   - config.set    — validate + atomic-write + reload config (credential-gated)
//
// The execVerdictFromContent helper mirrors handleExecFetch's gate matrix
// (execfetch.go) so byn.simulate can never drift from enforcement;
// agreement is pinned by cross-check tests in bynstudio_test.go.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/config"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// ── bynValidateContent runs the full validation matrix on raw .byn bytes and
// returns (errors, warnings). It is shared by handleBynValidate and the
// Content-write path in handleBynWrite.
//
// Error conditions (must be fixed):
//   - content > MaxSize                  → section "size"
//   - TOML parse error                   → section "toml"
//   - ValidateAuth error                 → section "auth"
//   - ValidateActions error              → section "exec"
//   - ValidateAliases error              → section "aliases"
//
// Warning conditions (advisory):
//   - env wildcard ("*" in Exec.Env)
//   - actions wildcard ("*" in Exec.Actions)
//   - empty/absent actions               → every exec will require authorization
//   - per-action {{args}} tail on any action
//   - ShellInterpreterWithPlaceholder on any action
//   - [auth] exec="none"                 → wildcard-equivalent (bypass)
//   - [auth] get/update/delete="none"    → bypass for vault data-plane ops
func bynValidateContent(content []byte) (errs, warns []ipc.BynIssue) {
	// Size cap.
	if len(content) > bynfile.MaxSize {
		errs = append(errs, ipc.BynIssue{
			Section: "size",
			Message: fmt.Sprintf(".byn exceeds 64 KiB (%d bytes); reduce its size", len(content)),
		})
		return errs, warns
	}

	// TOML parse.
	f, perr := bynfile.Parse(content)
	if perr != nil {
		errs = append(errs, ipc.BynIssue{Section: "toml", Message: perr.Error()})
		return errs, warns
	}

	// ValidateAuth.
	if verr := f.ValidateAuth(); verr != nil {
		errs = append(errs, ipc.BynIssue{Section: "auth", Message: verr.Error()})
	}
	// ValidateActions.
	if verr := f.ValidateActions(); verr != nil {
		errs = append(errs, ipc.BynIssue{Section: "exec", Message: verr.Error()})
	}
	// ValidateAliases.
	if verr := f.ValidateAliases(); verr != nil {
		errs = append(errs, ipc.BynIssue{Section: "aliases", Message: verr.Error()})
	}

	// Warnings.
	if f.AllowsAll() {
		warns = append(warns, ipc.BynIssue{
			Section: "exec",
			Message: `[exec] env = "*" injects ALL scope vars into every exec — consider an explicit list`,
		})
	}
	if f.ActionsAllowAll() {
		warns = append(warns, ipc.BynIssue{
			Section: "exec",
			Message: `[exec] actions = "*" allows every command to run re-auth-free — consider pinning specific actions`,
		})
	}
	// Empty/absent actions (and not wildcard): every exec needs per-action auth.
	if !f.ActionsAllowAll() && len(f.Exec.Actions) == 0 {
		warns = append(warns, ipc.BynIssue{
			Section: "exec",
			Message: "no [exec] actions — every byn exec will require authorization",
		})
	}
	// Per-action warnings from action patterns.
	for _, action := range f.Exec.Actions {
		if action == "*" {
			continue
		}
		pat, perr2 := bynfile.ParseActionPattern(action)
		if perr2 != nil {
			continue // parse error already reported as an error above
		}
		if pat.HasArgsTail() {
			warns = append(warns, ipc.BynIssue{
				Section: "exec",
				Message: fmt.Sprintf("action %q ends with {{args}} — any extra arguments are accepted without further matching", action),
			})
		}
		if bynfile.ShellInterpreterWithPlaceholder(pat) {
			warns = append(warns, ipc.BynIssue{
				Section: "exec",
				Message: fmt.Sprintf("action %q looks like a shell interpreter with a placeholder — injected env vars will be visible to the script", action),
			})
		}
	}
	// [auth] none warnings.
	if f.Auth["exec"] == "none" {
		warns = append(warns, ipc.BynIssue{
			Section: "auth",
			Message: `[auth] exec = "none" is equivalent to actions = "*" — every command runs re-auth-free`,
		})
	}
	for _, key := range []string{"get", "update", "delete"} {
		if f.Auth[key] == "none" {
			warns = append(warns, ipc.BynIssue{
				Section: "auth",
				Message: fmt.Sprintf(`[auth] %s = "none" bypasses the per-action auth gate for vault %s operations`, key, key),
			})
		}
	}
	return errs, warns
}

// ── handleBynValidate validates .byn content without trusting it. ──────────

func (d *Daemon) handleBynValidate(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.BynValidateReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}

	errs, warns := bynValidateContent(req.Content)

	d.auditEmit(ctx, vault.DefaultVaultName, audit.Event{
		Op: string(ipc.OpBynValidate), Outcome: audit.OutcomeOK,
	})

	out := ipc.BynValidateResp{
		Errors:   errs,
		Warnings: warns,
	}
	// Populate Parsed when there are zero errors so the portal can carry the
	// current entered values into the form/builder without a separate round-trip.
	if len(errs) == 0 {
		if f, perr := bynfile.Parse(req.Content); perr == nil {
			p := &ipc.BynParsed{}
			p.Scope.Vault = f.Scope.Vault
			p.Scope.Project = f.Scope.Project
			p.Scope.Env = f.Scope.Env
			p.Env = []string(f.Exec.Env)
			p.EnvWildcard = f.AllowsAll()
			p.Actions = []string(f.Exec.Actions)
			p.ActionsWildcard = f.ActionsAllowAll()
			if len(f.Aliases) > 0 {
				p.Aliases = f.Aliases
			}
			if len(f.Auth) > 0 {
				p.Auth = f.Auth
			}
			out.Parsed = p
		}
	}

	resp, rerr := ipc.NewResponse(env.ID, out)
	if rerr != nil {
		return internalErr(env.ID, rerr)
	}
	return resp
}

// ── execVerdict is the result of the shared verdict helper. ─────────────────

// ExecVerdictResult is the verdict output from execVerdictFromContent.
// It mirrors BynSimulateResp closely so the handler is just a thin wrapper.
type execVerdictResult struct {
	ResolvedArgv  []string
	MatchedKind   string // "action", "alias", "wildcard", "none"
	MatchedAction string
	MatchedAlias  string
	Free          bool
	Reason        string
}

// execVerdictFromContent derives the exec gate verdict from parsed .byn content
// and a tokenized argv. It mirrors handleExecFetch's [exec] actions gate matrix
// (see execfetch.go) so byn.simulate can never drift from enforcement.
//
// Gate matrix (mirrors handleExecFetch exactly):
//
//	[auth] exec = "always" → auth (reason: policy)
//	[auth] exec = "none"   → free (reason: policy)
//	default / "trusted":
//	  actions wildcard ("*") → free, kind=wildcard
//	  pattern match          → free, kind=action, matchedAction=pattern
//	  unmatched / empty      → auth, kind=none, reason=not pinned
//
// Alias expansion: if argv[0] matches an alias name, expand it from the
// aliases map first; set MatchedAlias.
//
// The record.Actions / record.Auth used by handleExecFetch are MAC-bound.
// Here we read directly from the parsed file (no record), so this function
// MUST NOT be used as an enforcement gate — only for simulation/display.
func execVerdictFromContent(f bynfile.File, argv []string) execVerdictResult {
	// Alias expansion: if the first token is an alias name, expand it.
	resolvedArgv := argv
	matchedAlias := ""
	if len(argv) > 0 {
		if val, ok := f.Aliases[argv[0]]; ok {
			matchedAlias = argv[0]
			resolvedArgv = append(strings.Fields(val), argv[1:]...)
		}
	}

	execPolicy := f.Auth["exec"] // "always", "none", "trusted", or ""

	// [auth] exec = "always": unconditional auth.
	if execPolicy == "always" {
		return execVerdictResult{
			ResolvedArgv: resolvedArgv,
			MatchedKind:  "none",
			MatchedAlias: matchedAlias,
			Free:         false,
			Reason:       `[auth] exec = "always" requires authorization for every command`,
		}
	}

	// [auth] exec = "none": always free (wildcard-equivalent).
	if execPolicy == "none" {
		return execVerdictResult{
			ResolvedArgv: resolvedArgv,
			MatchedKind:  "wildcard",
			MatchedAlias: matchedAlias,
			Free:         true,
			Reason:       `[auth] exec = "none": all commands run re-auth-free`,
		}
	}

	// Default / "trusted": check actions list.
	// Wildcard check.
	for _, a := range f.Exec.Actions {
		if a == "*" {
			return execVerdictResult{
				ResolvedArgv: resolvedArgv,
				MatchedKind:  "wildcard",
				MatchedAlias: matchedAlias,
				Free:         true,
				Reason:       `[exec] actions = "*": all commands run re-auth-free`,
			}
		}
	}

	// Pattern match.
	if len(resolvedArgv) > 0 {
		for _, a := range f.Exec.Actions {
			if a == "*" {
				continue
			}
			pat, perr := bynfile.ParseActionPattern(a)
			if perr != nil {
				continue // defense in depth: bad pattern is non-matching
			}
			if pat.Match(resolvedArgv) {
				return execVerdictResult{
					ResolvedArgv:  resolvedArgv,
					MatchedKind:   "action",
					MatchedAction: a,
					MatchedAlias:  matchedAlias,
					Free:          true,
					Reason:        fmt.Sprintf("command matched pinned action %q", a),
				}
			}
		}
	}

	// Unmatched (including empty actions or empty resolvedArgv).
	return execVerdictResult{
		ResolvedArgv: resolvedArgv,
		MatchedKind:  "none",
		MatchedAlias: matchedAlias,
		Free:         false,
		Reason:       "command not pinned in [exec] actions",
	}
}

// ── handleBynSimulate simulates the exec verdict. ──────────────────────────

func (d *Daemon) handleBynSimulate(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.BynSimulateReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}

	// Validate content first; invalid → CodeBadRequest with the first error.
	errs, _ := bynValidateContent(req.Content)
	if len(errs) > 0 {
		resp := badRequest(env.ID, fmt.Errorf("[%s] %s", errs[0].Section, errs[0].Message))
		d.auditEmit(ctx, vault.DefaultVaultName, audit.Event{
			Op:        string(ipc.OpBynSimulate),
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(ipc.CodeBadRequest),
		})
		return resp
	}

	// Parse (already validated above, so this should not fail).
	f, perr := bynfile.Parse(req.Content)
	if perr != nil {
		return badRequest(env.ID, perr)
	}

	argv := strings.Fields(req.CommandLine)
	verdict := execVerdictFromContent(f, argv)

	verdictStr := "auth"
	if verdict.Free {
		verdictStr = "free"
	}

	d.auditEmit(ctx, vault.DefaultVaultName, audit.Event{
		Op: string(ipc.OpBynSimulate), Outcome: audit.OutcomeOK,
	})

	resp, rerr := ipc.NewResponse(env.ID, ipc.BynSimulateResp{
		ResolvedArgv:  verdict.ResolvedArgv,
		MatchedKind:   verdict.MatchedKind,
		MatchedAction: verdict.MatchedAction,
		MatchedAlias:  verdict.MatchedAlias,
		Verdict:       verdictStr,
		Reason:        verdict.Reason,
	})
	if rerr != nil {
		return internalErr(env.ID, rerr)
	}
	return resp
}

// ── handleBynRead reads a .byn file with its current trust status. ──────────

func (d *Daemon) handleBynRead(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.BynReadReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	if req.Path == "" {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "path required", "")
	}

	// Canonicalize FIRST (resolves symlinks), then check the basename on the
	// resolved path. Checking filepath.Base(req.Path) before EvalSymlinks would
	// allow a symlink named ".byn" pointing at an arbitrary file (e.g.
	// ~/.ssh/id_rsa) to bypass the guard — the raw path passes (".byn") but
	// Canonicalize would redirect the read to the symlink target.
	canon := trust.Canonicalize(req.Path)

	// Security: only .byn files may be read via this endpoint. Reject any
	// path whose RESOLVED final component is not exactly ".byn" so the portal
	// cannot act as an arbitrary file-read oracle (e.g. /etc/hosts,
	// ~/.ssh/config) even via a symlink named ".byn".
	if filepath.Base(canon) != ".byn" {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			"only .byn files can be read", "supply the path to a .byn file")
	}

	body, fi, rerr := readBynFile(canon)
	if rerr != nil {
		d.auditEmit(ctx, vault.DefaultVaultName, audit.Event{
			Op:        string(ipc.OpBynRead),
			Outcome:   audit.OutcomeDenied,
			BynPath:   canon,
			ErrorCode: string(ipc.CodeBadRequest),
		})
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			fmt.Sprintf("read %s: %v", canon, rerr), "check the path and retry")
	}

	var currentMTime int64
	if fi != nil {
		currentMTime = fi.ModTime().UnixNano()
	}
	hash := trust.Hash(body)

	// Derive vk-MAC key if the default vault is unlocked.
	var vkKey []byte
	if st, errEnv := d.storeForVault(env.ID, vault.DefaultVaultName); errEnv == nil && !st.IsLocked() {
		if k, derr := st.DeriveSubkey(trust.VKMACKeyInfo); derr == nil {
			vkKey = k
			defer zeroBytes(vkKey)
		}
	}

	status, _, verr := trust.Verify(d.cfg.Dir, canon, hash, currentMTime, d.fpMACKey, vkKey)
	if verr != nil {
		return internalErr(env.ID, verr)
	}

	d.auditEmit(ctx, vault.DefaultVaultName, audit.Event{
		Op: string(ipc.OpBynRead), Outcome: audit.OutcomeOK, BynPath: canon,
	})

	// Attempt to populate Parsed for the portal builder pre-population.
	// Parse failure is soft: we set ParseError and leave Parsed nil so the
	// portal can fall back to raw mode with a notice. Content must be
	// non-empty to bother trying.
	resp := ipc.BynReadResp{
		Path:        canon,
		Content:     body,
		TrustStatus: string(status),
	}
	if len(body) > 0 {
		if f, perr := bynfile.Parse(body); perr != nil {
			resp.ParseError = perr.Error()
		} else {
			p := &ipc.BynParsed{}
			p.Scope.Vault = f.Scope.Vault
			p.Scope.Project = f.Scope.Project
			p.Scope.Env = f.Scope.Env
			p.Env = []string(f.Exec.Env)
			p.EnvWildcard = f.AllowsAll()
			p.Actions = []string(f.Exec.Actions)
			p.ActionsWildcard = f.ActionsAllowAll()
			if len(f.Aliases) > 0 {
				p.Aliases = f.Aliases
			}
			if len(f.Auth) > 0 {
				p.Auth = f.Auth
			}
			resp.Parsed = p
		}
	}

	out, rerr2 := ipc.NewResponse(env.ID, resp)
	if rerr2 != nil {
		return internalErr(env.ID, rerr2)
	}
	return out
}

// ── handleConfigGet reads the raw config file bytes. ────────────────────────

func (d *Daemon) handleConfigGet(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ConfigGetReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}

	cfgPath := config.Path(d.cfg.Dir)
	content, err := os.ReadFile(cfgPath) // #nosec G304 — daemon-owned dir
	if err != nil && !os.IsNotExist(err) {
		return internalErr(env.ID, err)
	}
	// When absent, content stays nil (empty); parse Default() so the portal
	// visual editor can pre-populate with the correct defaults.

	d.auditEmit(ctx, vault.DefaultVaultName, audit.Event{
		Op: string(ipc.OpConfigGet), Outcome: audit.OutcomeOK,
	})

	// Populate Parsed: absent file → Default(); present file → Parse().
	// A parse error is soft: set ParseError and leave Parsed nil so the portal
	// falls back to raw mode with a notice (mirrors the byn.read pattern).
	cfgResp := ipc.ConfigGetResp{
		Path:    cfgPath,
		Content: content,
	}
	if len(content) == 0 {
		// Absent file: use defaults, no parse error.
		def := config.Default()
		cfgResp.Parsed = configParsedFromConfig(def)
	} else {
		parsed, perr := config.Parse(content)
		if perr != nil {
			cfgResp.ParseError = perr.Error()
			// Parsed stays nil; portal falls back to raw mode.
		} else {
			cfgResp.Parsed = configParsedFromConfig(parsed)
		}
	}

	resp, rerr := ipc.NewResponse(env.ID, cfgResp)
	if rerr != nil {
		return internalErr(env.ID, rerr)
	}
	return resp
}

// configParsedFromConfig converts a config.Config into the wire-level
// ConfigParsed for the portal's visual settings editor.
func configParsedFromConfig(c config.Config) *ipc.ConfigParsed {
	return &ipc.ConfigParsed{
		UIEnabled:       c.UI.Enabled,
		UIPort:          c.UI.Port,
		IdleTimeout:     time.Duration(c.Daemon.IdleTimeout).String(),
		RevealHideAfter: time.Duration(c.UI.RevealHideAfter).String(),
		PerActionAuth:   c.Security.PerActionAuth,
	}
}

// ── handleConfigValidate validates config content without writing it. ───────

func (d *Daemon) handleConfigValidate(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ConfigValidateReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}

	d.auditEmit(ctx, vault.DefaultVaultName, audit.Event{
		Op: string(ipc.OpConfigValidate), Outcome: audit.OutcomeOK,
	})

	out := ipc.ConfigValidateResp{}
	parsed, perr := config.Parse(req.Content)
	if perr != nil {
		out.Errors = []ipc.BynIssue{{Section: "toml", Message: perr.Error()}}
	} else {
		out.Parsed = configParsedFromConfig(parsed)
	}

	resp, rerr := ipc.NewResponse(env.ID, out)
	if rerr != nil {
		return internalErr(env.ID, rerr)
	}
	return resp
}

// ── handleConfigSet validates, writes, and reloads the config. ──────────────

func (d *Daemon) handleConfigSet(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ConfigSetReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zeroBytes(req.Password)

	// Credential gate FIRST — changing config is a daemon-global action.
	// Route through authorizeActionAlways (the "default" vault is the config vault).
	vaultName := vault.DefaultVaultName
	st, errEnv := d.storeForVault(env.ID, vaultName)
	if errEnv != nil {
		return errEnv
	}
	if le := d.authorizeActionAlways(ctx, env.ID, vaultName, st,
		"changing byn configuration requires authorization",
		"supply the master password or use a passkey",
		req.Password, req.PresenceToken); le != nil {
		d.auditEmit(ctx, vaultName, audit.Event{
			Op:        string(ipc.OpConfigSet),
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(le.Err.Code),
		})
		return le
	}

	// Validate the new content via config.Parse (round-trip; no disk write yet).
	if _, verr := config.Parse(req.Content); verr != nil {
		d.auditEmit(ctx, vaultName, audit.Event{
			Op:        string(ipc.OpConfigSet),
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(ipc.CodeBadRequest),
		})
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			fmt.Sprintf("invalid config: %v", verr),
			"fix the config TOML and retry")
	}

	// Atomic write to the config path (0600) — write to tmp, then rename.
	cfgPath := config.Path(d.cfg.Dir)
	tmp := cfgPath + ".tmp"
	if werr := os.WriteFile(tmp, req.Content, 0o600); werr != nil { // #nosec G304
		d.auditEmit(ctx, vaultName, audit.Event{
			Op:        string(ipc.OpConfigSet),
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(ipc.CodeInternal),
		})
		return internalErr(env.ID, werr)
	}
	if rerr := os.Rename(tmp, cfgPath); rerr != nil {
		d.auditEmit(ctx, vaultName, audit.Event{
			Op:        string(ipc.OpConfigSet),
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(ipc.CodeInternal),
		})
		return internalErr(env.ID, rerr)
	}

	// Reload — apply the new settings live.
	changes, rerr := d.Reload()
	if rerr != nil {
		// Reload failed after write — config is on disk but in-memory state may differ.
		d.auditEmit(ctx, vaultName, audit.Event{
			Op:        string(ipc.OpConfigSet),
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(ipc.CodeInternal),
		})
		changes = append(changes, fmt.Sprintf("config written; reload failed: %v — restart the daemon", rerr))
		resp, rerr2 := ipc.NewResponse(env.ID, ipc.ConfigSetResp{ChangeNotes: changes})
		if rerr2 != nil {
			return internalErr(env.ID, rerr2)
		}
		return resp
	}

	d.auditEmit(ctx, vaultName, audit.Event{
		Op: string(ipc.OpConfigSet), Outcome: audit.OutcomeOK,
	})

	resp, rerr2 := ipc.NewResponse(env.ID, ipc.ConfigSetResp{ChangeNotes: changes})
	if rerr2 != nil {
		return internalErr(env.ID, rerr2)
	}
	return resp
}
