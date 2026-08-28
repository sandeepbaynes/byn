package daemon

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// handleExecFetch authorizes a `byn exec` and returns the values to
// inject, enforcing BOTH the [exec] env allowlist AND the [exec] actions
// pinlist SERVER-side (NU-1 + NU-2; spec §4.4).
//
// Security argument for reading actions/auth from the MAC-bound TRUST RECORD
// rather than re-parsing the file:
//   - The trust record (Actions, Auth fields) was written at GRANT TIME by the
//     daemon after verifying the master password and MAC'ing the policy into the
//     record. The vk-MAC verification above already proved this record is
//     genuine (bound to this machine + this vault key). Reading policy from the
//     record is therefore tamper-evident: a rogue that edits the .byn AFTER
//     trust is granted cannot change the effective policy without re-trusting
//     (which requires the password).
//   - The .byn content is still read and parsed for the [exec] env allowlist
//     (existing code) because env filtering is a content operation; the actions
//     and auth policy are explicitly stored in the record for exactly this use.
//   - Stale records (no MACs) are rejected as VerifyStale by the trust gate
//     above, so they never reach here — v1/stale records never have Actions.
//
// [exec] actions gate matrix (NU-2; applies to trusted-path exec only):
//
//	policy "always"   (record.Auth["exec"] == "always") → ALWAYS per-action auth,
//	                  even for matched or wildcard actions.
//	policy "none"     (record.Auth["exec"] == "none")   → NEVER auth; any command
//	                  runs free. Equivalent to actions "*" but bypasses the loud
//	                  warning at exec time (the warning was shown at grant time,
//	                  Task 3). Document as wildcard-equivalent.
//	policy default/absent/trusted:
//	  actions wildcard ("*" in record.Actions)          → free + ActionsWildcard flag
//	  matched (pattern match against resolvedArgv)       → free
//	  unmatched (incl. empty actions, empty resolvedArgv)→ per-action auth required
//	                                                       (authorizeActionAlways path,
//	                                                        independent of global flag)
//
// The session gate governs operations WITHOUT a .byn contract (ad-hoc exec,
// get, put, delete, …). For trusted-.byn exec, the [exec] actions list IS
// the contract — it applies regardless of session state. The spec requires
// this independence: the session gate must not silently make every trusted-.byn
// exec require a password (the .byn already carries its own auth policy).
//
// Action matching is PATTERN-based (NU-2.1): each record action is compiled
// via bynfile.ParseActionPattern and matched against the resolved argv. Parse
// errors on record actions (e.g. a hand-MAC'd record with a bad pattern) are
// treated as NON-matching (defense in depth — never panics, never widens).
// Arguments containing literal spaces cannot be represented; quote-aware
// matching is future work.
//
// Alias expansion (NU-2.1): when req.Alias is non-empty, the daemon looks up
// the alias in record.Aliases, appends req.Argv (extra args), and runs the
// RESOLVED argv through the same gate matrix. Alias exec requires Path to be
// set — aliases live in the trusted .byn. The CLI must exec ResolvedArgv
// (returned in the response) exactly.
//
// Ad-hoc exec (Path="") uses whole-scope injection, gated by the session gate
// (no actions concept for ad-hoc).
func (d *Daemon) handleExecFetch(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ExecFetchReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	values, resolvedArgv, wildcard, noneDeclared, actionsWildcard, missing, unattended, le := d.authorizeExec(ctx, env.ID, req)
	if le != nil {
		// authorizeExec already audited the denial.
		return le
	}
	resp, rerr := ipc.NewResponse(env.ID, ipc.ExecFetchResp{
		Values:           values,
		Wildcard:         wildcard,
		NoneDeclared:     noneDeclared,
		ActionsWildcard:  actionsWildcard,
		ResolvedArgv:     resolvedArgv,
		MissingValues:    missing,
		UnattendedValues: unattended,
		GrantExpiresAt:   d.grantExpiryFor(req, resolvedArgv),
	})
	if rerr != nil {
		// authorizeExec already audited success; an encode failure here is
		// vanishingly rare, returned as an internal error without re-auditing.
		return internalErr(env.ID, rerr)
	}
	return resp
}

// authorizeExec runs the FULL exec authorization (lock check, ad-hoc/session
// gate, trust verify, [exec] actions gate, alias expansion) and fetches the
// allowlisted values. It is shared by handleExecFetch (returns values to the
// CLI) and handleExecSpawn (spawns the child server-side). Returns an error
// envelope (already audited) on denial. On success: the injected values, the
// resolved argv, and the response flags.
//
// The audit emission lives HERE (not in handleExecFetch) so exec.fetch and
// exec.spawn audit the AUTHORIZATION decision identically — both share this one
// emission. handleExecFetch must NOT re-audit on success (it would double-count);
// handleExecSpawn likewise relies on this single auth audit and only emits an
// additional event if the spawn itself FAILS after a clean authorization.
func (d *Daemon) authorizeExec(ctx context.Context, id string, req ipc.ExecFetchReq) (
	values []ipc.ExecFetchValue, resolvedArgv []string,
	wildcard, noneDeclared, actionsWildcard bool, missing, unattended []string, le *ipc.Envelope) {

	st, scope, errEnv := d.scopeFor(id, req.Scope)
	if errEnv != nil {
		return nil, nil, false, false, false, nil, nil, errEnv
	}

	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
	canon := ""
	if req.Path != "" {
		canon = trust.Canonicalize(req.Path)
	}
	// auditCmd is updated after alias expansion to include the resolved form.
	// We start with req.Command (the CLI-side label) and override it after
	// alias lookup. For alias execs the audit event is:
	//   "alias <name> → <resolved joined, 200-cap>"
	auditCmd := req.Command
	auditExec := func(resp *ipc.Envelope) {
		outcome, code := outcomeFor(resp)
		d.auditEmit(ctx, vaultName, audit.Event{
			Op: "exec", Outcome: outcome, BynPath: canon,
			Command: auditCmd, ErrorCode: code,
		})
	}

	// Lock check applies to AD-HOC exec only (no .byn): it injects the whole
	// scope via the in-memory vault key, so it needs an unlocked vault. A
	// trusted-.byn exec does NOT — it decrypts only the allowlisted vars via the
	// .byn's sealed exec capability (machine-fingerprint keyed, no vault key), so
	// it runs autonomously while LOCKED. That is the core promise: agents run
	// after a reboot with no password.
	if req.Path == "" && st.IsLocked() {
		le := ipc.NewError(id, ipc.CodeLocked, "vault is locked", "byn unlock")
		auditExec(le)
		return nil, nil, false, false, false, nil, nil, le
	}

	// Alias exec requires a .byn — aliases are defined in the trust record.
	if req.Alias != "" && req.Path == "" {
		le := ipc.NewError(id, ipc.CodeBadRequest,
			"aliases require a trusted .byn; no path was provided",
			"run from a directory with a trusted .byn that defines [aliases]")
		auditExec(le)
		return nil, nil, false, false, false, nil, nil, le
	}

	// Auth gate for ad-hoc exec (Path=""). Sessions NEVER bless exec: the
	// NU-3 matrix does not allow a session token to substitute for explicit
	// credentials when exec hands out the whole scope. Trusted-.byn exec
	// (Path!="") has its own [exec] actions gate below — the .byn contract
	// is the authorization for that path and is independent of this gate.
	// Ad-hoc exec always requires fresh credentials (password or presence
	// token) because it exposes the entire vault scope without an env
	// allowlist, making ambient session-based authorization too broad.
	if req.Path == "" {
		if len(req.Password) == 0 && len(req.PresenceToken) == 0 {
			// No credentials supplied: emit the exec-specific message so the
			// user understands that running from a trusted .byn is an alternative.
			le := ipc.NewError(id, ipc.CodeAuthRequired,
				"ad-hoc exec requires authorization (sessions do not authorize exec; use a trusted .byn or supply credentials)",
				"run from a directory with a trusted .byn, or supply the master password")
			auditExec(le)
			return nil, nil, false, false, false, nil, nil, le
		}
		// Credentials present: verify UNCONDITIONALLY via authorizeActionAlways
		// — NOT via authorizeAction (which would permit session bypass).
		//
		// WHY: ad-hoc exec presents no .byn file. The [auth] policy in a
		// .byn frees only that .byn's own contract (exec WITH a specific
		// file, which also carries an env allowlist). Ad-hoc exec has no
		// such contract — it hands out the WHOLE scope with no env allowlist.
		// Using authorizeAction here would let a session or a trusted .byn in
		// the same scope with [auth] exec="none" silently skip credential
		// verification and inject ALL scope vars for ANY ad-hoc command.
		// authorizeActionAlways bypasses policyFor and session check entirely,
		// ensuring fresh credentials are always required for ad-hoc exec.
		if le := d.authorizeActionAlways(ctx, id, vaultName, st,
			"ad-hoc exec requires authorization (supply credentials or use a trusted .byn)",
			"run from a directory with a trusted .byn, or supply the master password",
			req.Password, req.PresenceToken); le != nil {
			auditExec(le)
			return nil, nil, false, false, false, nil, nil, le
		}
	}

	var allow []string
	// Names the .byn marks as fine to be absent; they are injected when present
	// and never reported missing.
	var optionalEnv []string
	// finalArgv is the argv the daemon authorizes and returns to the CLI.
	// For direct exec it is req.Argv; for alias exec it is the expanded form.
	// It is set inside the req.Path != "" block and passed back in ResolvedArgv.
	var finalArgv []string

	if req.Path != "" {
		body, fi, rerr := readBynFile(canon)
		if rerr != nil {
			// Default: the daemon couldn't read the file → treat as untrusted.
			// But if the OS BLOCKED the read (macOS TCC / no Full Disk Access),
			// surface THAT instead of a misleading "untrusted" — the fix is FDA,
			// not re-trusting. (Same actionable message trust grant already shows.)
			msg, hint := canon+" is untrusted (unreadable or oversize)", "byn trust "+canon
			if errors.Is(rerr, errDaemonAccessDenied) {
				msg, hint = rerr.Error(), "grant the daemon Full Disk Access, or move the project — see the message above"
			}
			le := ipc.NewError(id, ipc.CodeTrustDenied, msg, hint)
			auditExec(le)
			return nil, nil, false, false, false, nil, nil, le
		}
		// Use the mtime from the Stat performed inside readBynFile. A nil fi
		// is safe: zero mtime falls back to v1 records ignoring it.
		var currentMTime int64
		if fi != nil {
			currentMTime = fi.ModTime().UnixNano()
		}
		// Use-time trust gate. fp-MAC always; vk-MAC ONLY when the vault is
		// unlocked (the vk key needs the in-memory vault key). Autonomous exec
		// runs locked → vkKey is nil and the machine-fingerprint fp-MAC is the
		// tamper-evidence (same machine binding as the capability itself).
		var vkKey []byte
		if !st.IsLocked() {
			k, derr := st.DeriveSubkey(trust.VKMACKeyInfo)
			if derr != nil {
				resp := mapVaultErr(id, derr)
				auditExec(resp)
				return nil, nil, false, false, false, nil, nil, resp
			}
			vkKey = k
			defer zeroBytes(vkKey)
		}

		status, _, rec, verr := trust.Verify(d.cfg.Dir, canon, trust.Hash(body), currentMTime, d.fpMACKey, vkKey)
		if verr != nil {
			ie := internalErr(id, verr)
			auditExec(ie)
			return nil, nil, false, false, false, nil, nil, ie
		}
		// A changed file is only a problem if it asks for more than was
		// granted. Reformatting, a reordered list, an added comment, or a branch
		// switch that rewrites mtimes all land here, and none of them are a
		// request for new authority — blocking on them stopped every command in
		// the project until a human retyped the master password.
		if status == trust.VerifyChanged {
			effective, delta, ok := reconcileChanged(rec, body)
			// A widening made entirely of variables this same caller created
			// discloses nothing it does not already hold, so it is granted here
			// rather than parked for a human who would only be rubber-stamping
			// the agent's own value back to it.
			if !ok && d.forgivesSelfAuthored(ctx, st, rec, delta, vaultName, vault.Scope{
				Project: defaultIfEmpty(rec.ScopeProject, vault.DefaultProjectName),
				Env:     defaultIfEmpty(rec.ScopeEnv, vault.DefaultEnvName),
			}) {
				ok = true
				d.auditEmit(ctx, vaultName, audit.Event{
					Project: rec.ScopeProject,
					Env:     rec.ScopeEnv,
					BynPath: canon,
					Op:      "trust_self_authored_grant",
					Outcome: audit.OutcomeOK,
				})
			}
			switch {
			case ok:
				status = trust.VerifyTrusted
				rec = applyPolicy(rec, effective)
			case delta.NeedsApproval():
				// Genuinely asking for more than was granted. Raise it for a
				// human and tell the caller where to look, instead of dying on
				// a password prompt no agent can answer.
				le := d.raiseTrustApproval(ctx, id, canon, vaultName, req, delta)
				auditExec(le)
				return nil, nil, false, false, false, nil, nil, le
			}
		}
		if status != trust.VerifyTrusted {
			le := ipc.NewError(id, ipc.CodeTrustDenied,
				trustDenyMessage(canon, status), "byn trust "+canon)
			auditExec(le)
			return nil, nil, false, false, false, nil, nil, le
		}
		if rec.Path == "" {
			// Verify said Trusted but returned no record — should be
			// impossible, but be defensive.
			le := ipc.NewError(id, ipc.CodeTrustDenied,
				canon+" is untrusted (record missing after verify)", "byn trust "+canon)
			auditExec(le)
			return nil, nil, false, false, false, nil, nil, le
		}
		f, perr := bynfile.Parse(body)
		if perr != nil {
			be := badRequest(id, perr)
			auditExec(be)
			return nil, nil, false, false, false, nil, nil, be
		}
		allow = []string(f.Exec.Env)
		optionalEnv = f.Exec.Optional
		wildcard = f.AllowsAll()
		noneDeclared = !wildcard && len(allow) == 0

		// ── [exec] actions gate (NU-2) ─────────────────────────────────────
		// Read actions/auth from the MAC-bound trust record (not the parsed
		// file) because the record was MAC'd at grant time — editing the .byn
		// after trust cannot change the effective policy (see security argument
		// in the function doc above). The file parse above is for [exec] env
		// filtering only; actions/auth are record-authoritative.
		// rec is already populated from Verify above — no second Lookup needed.

		// ── Alias expansion (NU-2.1) ──────────────────────────────────────
		// When the CLI sent an alias name, resolve it from the MAC-bound
		// record (not the live file — same tamper-evidence argument as for
		// actions/auth). The resolved argv = alias value tokens + extra args.
		resolvedArgv := req.Argv // default: direct form, argv is full argv
		if req.Alias != "" {
			value, aliasOK := rec.Aliases[req.Alias]
			if !aliasOK {
				// Build a hint listing available alias names (capped to 8).
				names := make([]string, 0, len(rec.Aliases))
				for n := range rec.Aliases {
					names = append(names, n)
				}
				sort.Strings(names)
				if len(names) > 8 {
					names = names[:8]
				}
				hint := fmt.Sprintf("alias %q is not defined in %s [aliases]", req.Alias, canon)
				if len(names) > 0 {
					hint += "; available: " + strings.Join(names, ", ")
				} else {
					hint += "; no aliases are defined"
				}
				le := ipc.NewError(id, ipc.CodeNotFound, hint, "")
				auditExec(le)
				return nil, nil, false, false, false, nil, nil, le
			}
			// Expand: alias base tokens + extra passthrough args.
			resolvedArgv = append(strings.Fields(value), req.Argv...)
			// Update the audit command to reflect the expansion (200-char cap).
			aliasLabel := "alias " + req.Alias + " → " + strings.Join(resolvedArgv, " ")
			const maxAuditLen = 200
			if len(aliasLabel) > maxAuditLen {
				aliasLabel = aliasLabel[:maxAuditLen] + "…"
			}
			auditCmd = aliasLabel
		}

		// --no-privsep (ForceAuth): the child runs as the OWNER, so the injected
		// env is visible to the owner's `ps -E`. Require the master password EVERY
		// run — NO blind trusted-file run — overriding the .byn's [exec] actions /
		// [auth] policy. (Owner decision 2026-06-17: non-privsep/debug runs are
		// always interactive, so a password per run is acceptable.) Privsep exec
		// leaves ForceAuth false: the trusted .byn + pinned action is the authority.
		if req.ForceAuth {
			if le := d.authorizeActionAlways(ctx, id, vaultName, st,
				"non-privsep exec requires the master password (the child runs as you, exposing the injected env)",
				"supply the master password; or run with privsep (default) for credential-free trusted exec",
				req.Password, req.PresenceToken); le != nil {
				auditExec(le)
				return nil, nil, false, false, false, nil, nil, le
			}
		} else {

			// Derive exec policy from the trust record's Auth table.
			execPolicy := rec.Auth["exec"] // "always", "none", "trusted", or ""

			if execPolicy != "always" && execPolicy != "none" {
				// Default / "trusted" branch: check the actions list.
				actionsWild := false
				for _, a := range rec.Actions {
					if a == "*" {
						actionsWild = true
						break
					}
				}

				if actionsWild {
					// Wildcard: all commands run free. Set flag so CLI warns.
					actionsWildcard = true
				} else {
					// Pattern match: compile each record action via ParseActionPattern
					// and call Match against resolvedArgv. This handles typed
					// placeholders ({{uuid}}, {{args}}, etc.) as well as plain
					// literals. DEFENSE IN DEPTH: a record action that fails to parse
					// (e.g. a hand-MAC'd record with a bad pattern string) is treated
					// as NON-matching — it never panics, never widens the gate.
					// Empty resolvedArgv (old CLI / version skew, or alias that
					// expanded to nothing) is treated as unmatched → fail-closed.
					matched := false
					// Match the argv as sent AND with argv[0] symlink-resolved.
					// Trust records canonicalize their path, but `byn exec`
					// only absolutizes argv[0], so under a symlinked project
					// dir (macOS temp dirs live under /var -> /private/var) the
					// pinned pattern and the incoming command are the same file
					// spelled two ways. Comparing one spelling refuses a
					// command the .byn genuinely pins.
					candidates := [][]string{resolvedArgv}
					if len(resolvedArgv) > 0 {
						if resolved, rerr := filepath.EvalSymlinks(resolvedArgv[0]); rerr == nil && resolved != resolvedArgv[0] {
							alt := append([]string(nil), resolvedArgv...)
							alt[0] = resolved
							candidates = append(candidates, alt)
						}
					}
					if len(resolvedArgv) > 0 {
						for _, a := range rec.Actions {
							if a == "*" {
								continue // already handled above
							}
							pat, perr := bynfile.ParseActionPattern(a)
							if perr != nil {
								// Defense in depth: bad pattern → skip (non-matching).
								continue
							}
							for _, cand := range candidates {
								if pat.Match(cand) {
									matched = true
									break
								}
							}
							if matched {
								break
							}
						}
					}

					// A command someone already approved for this .byn runs, without
					// asking again. Approving has to actually grant something: a
					// decision that is recorded and then changes nothing leaves the
					// caller stopped at the same gate on its very next attempt, told
					// each time that approval was granted. That is a worse dead end
					// than the one the queue replaced, because it looks like progress.
					if !matched && d.actionApproved(canon, req.Command, resolvedArgv) {
						matched = true
						d.auditEmit(ctx, vaultName, audit.Event{
							Op: "exec.action_approved", Outcome: audit.OutcomeOK, BynPath: canon,
							Command: strings.Join(resolvedArgv, " "),
						})
					}

					if !matched {
						// Unmatched (includes empty actions AND empty resolvedArgv): gate.
						// authorizeActionAlways is used here — the .byn contract
						// requires credential verification UNCONDITIONALLY, independent
						// of session state.
						msg := "command not pinned in " + canon + " [exec] actions"
						recoverHint := "add it to [exec] actions and re-trust, or supply the password"
						// A caller with no credential to offer cannot answer this,
						// and this is the gate agents meet most: running a command
						// the .byn does not pin. Ending it at "auth: not a terminal"
						// stopped the run dead and sent a person back to
						// `make byn-trust`, which is the loop the queue exists to
						// break. Raise it as a decision instead, so the caller gets
						// an id and the work resumes once someone answers.
						if len(req.Password) == 0 && len(req.PresenceToken) == 0 {
							le := d.raiseActionApproval(ctx, id, canon, vaultName, req, resolvedArgv)
							auditExec(le)
							return nil, nil, false, false, false, nil, nil, le
						}
						if le := d.authorizeActionAlways(ctx, id, vaultName, st, msg, recoverHint,
							req.Password, req.PresenceToken); le != nil {
							auditExec(le)
							return nil, nil, false, false, false, nil, nil, le
						}
					}
					// matched → fall through (free)
				}
			} else if execPolicy == "always" {
				// auth = "always": require fresh auth even for matched/wildcard.
				// authorizeActionAlways is used here — the [auth] exec="always"
				// contract requires verification UNCONDITIONALLY, independent of
				// session state.
				msg := "[auth] exec = \"always\" requires authorization for every command"
				recoverHint := "supply the password or presence token"
				if le := d.authorizeActionAlways(ctx, id, vaultName, st, msg, recoverHint,
					req.Password, req.PresenceToken); le != nil {
					auditExec(le)
					return nil, nil, false, false, false, nil, nil, le
				}
			}
			// execPolicy == "none": no auth for any command — wildcard-equivalent.
			// The loud warning was shown at grant time (Task 3 displays the policy).
		}

		// Capture the authorized argv for the response. The CLI executes
		// exactly this, giving a single authoritative contract.
		finalArgv = resolvedArgv

		// Inject the allowlisted vars. PREFER the sealed exec capability (no vault
		// key — works while LOCKED, autonomous). Fall back to the vault-key path
		// for a trusted record that predates capabilities (requires unlock); if
		// it's locked AND has no capability, ask the user to unlock or re-trust.
		var le *ipc.Envelope
		switch {
		case noneDeclared:
			// The .byn declares no env to inject — nothing to decrypt, so no
			// vault key or capability is needed; it runs (subject to the actions
			// gate above) even while locked.
			values = nil
		case len(rec.ExecCapability) > 0:
			values, le = d.execValuesFromCapability(ctx, id, st, scope, rec)
		case !st.IsLocked():
			values, le = d.execValuesFromVaultKey(ctx, id, st, scope, allow, wildcard)
		default:
			le = ipc.NewError(id, ipc.CodeLocked,
				"this trusted .byn has no stored exec capability (granted before autonomous exec); unlock once or re-trust to enable it",
				"byn unlock, or re-trust: byn trust "+canon)
		}
		if le != nil {
			auditExec(le)
			return nil, nil, false, false, false, nil, nil, le
		}
	}

	if req.Path == "" {
		// Ad-hoc exec: inject the whole scope via the in-memory vault key
		// (unlock was enforced at the top for this path).
		var le *ipc.Envelope
		values, le = d.execValuesFromVaultKey(ctx, id, st, scope, nil, true)
		if le != nil {
			auditExec(le)
			return nil, nil, false, false, false, nil, nil, le
		}
	}
	d.touchVault(req.Scope.Vault)
	// Success: emit the single authorization audit here (outcome "ok"), so both
	// exec.fetch and exec.spawn audit the authorization identically. The nil
	// envelope passed to auditExec yields outcome "ok" (see outcomeFor) — the
	// audit does not depend on the eventual wire response, only on the verdict.
	auditExec(nil)
	resolvedArgv = finalArgv
	// Which of the injected values arrived with nobody behind them. Computed
	// here, beside the missing-value check, because the two answer the same
	// question from opposite sides: one names what the program will not get,
	// the other what it will get from a source no person vouched for.
	var invented []string
	if d.authored != nil {
		k := authoredScopeKey(req.Scope.Vault, scope, "")
		flagged := make(map[string]struct{})
		for _, n := range d.authored.UnattendedNamesFor(k.Vault, k.Project, k.Env) {
			flagged[n] = struct{}{}
		}
		for _, v := range values {
			if _, ok := flagged[v.Name]; ok {
				invented = append(invented, v.Name)
			}
		}
		sort.Strings(invented)
	}
	return values, resolvedArgv, wildcard, noneDeclared, actionsWildcard,
		missingAllowlisted(allow, optionalEnv, wildcard, values), invented, nil
}

// execValuesFromCapability decrypts a trusted .byn's allowlisted vars via its
// sealed exec capability (rec.ExecCapability) — using ONLY the machine
// fingerprint, no vault key, so it works while the vault is LOCKED. The
// capability's keys ARE the allowlist resolved at grant time, so we iterate
// them directly. An empty capability (a .byn with no [exec] env, or a record
// granted before capabilities existed) injects nothing. A captured var that has
// since been deleted is skipped; any other decrypt failure fails the exec.
func (d *Daemon) execValuesFromCapability(ctx context.Context, id string, st *vault.Store, scope vault.Scope, rec trust.Record) ([]ipc.ExecFetchValue, *ipc.Envelope) {
	if len(rec.ExecCapability) == 0 {
		return nil, nil // nothing to inject
	}
	if d.fpMACKey == nil {
		return nil, ipc.NewError(id, ipc.CodeLocked,
			"this machine has no fingerprint, so the trusted .byn's exec capability can't be unsealed",
			"unlock the vault and re-run, or re-trust on this machine")
	}
	capKey, err := vcrypto.DeriveCapKey(d.fpMACKey)
	if err != nil {
		return nil, internalErr(id, err)
	}
	defer zeroBytes(capKey)
	rowKeys, err := vcrypto.OpenCapability(capKey, rec.ExecCapability)
	if err != nil {
		return nil, ipc.NewError(id, ipc.CodeTrustDenied,
			"the trusted .byn's exec capability could not be unsealed on this machine",
			"re-trust on this machine: byn trust "+rec.Path)
	}
	defer func() {
		for _, k := range rowKeys {
			zeroBytes(k)
		}
	}()

	// The capability's keys are the allowlist as it stood at grant time. If the
	// file has since dropped a variable, that is a narrowing the author asked
	// for and it applies immediately — so injection is intersected with the
	// allowlist currently in force. (A file that ADDED a name never reaches
	// here: that is a widening and is refused until approved.)
	allowed := rec.EnvAllowlist()

	// A wildcard grant carries the scope key, which derives a row key for any
	// entry in the scope — including ones written after the grant. Without it,
	// "*" meant only the variables that existed at grant time, so a variable
	// another agent added was silently missing until someone re-trusted.
	scopeKey, hasScopeKey := rowKeys[vault.CapScopeKeyName]

	values := make([]ipc.ExecFetchValue, 0, len(rowKeys))
	seen := make(map[string]struct{}, len(rowKeys))
	if hasScopeKey {
		infos, lerr := st.ListEnvVars(ctx, scope)
		if lerr != nil {
			return nil, internalErr(id, fmt.Errorf("list scope for wildcard capability: %w", lerr))
		}
		for _, info := range infos {
			val, verr := st.OpenEnvVarWithScopeKey(ctx, scope, info.Name, scopeKey)
			if verr != nil {
				// Entries still on an older scheme cannot be derived from a
				// scope key; the per-row keys captured alongside cover them.
				if vault.ErrScopeKeyUnsupported(verr) || errors.Is(verr, vault.ErrNotFound) {
					continue
				}
				return nil, internalErr(id, fmt.Errorf("decrypt %q via scope key: %w", info.Name, verr))
			}
			seen[info.Name] = struct{}{}
			values = append(values, ipc.ExecFetchValue{Name: info.Name, Value: val})
		}
	}

	// Values the agent wrote while the vault was locked are sealed under the
	// scope's authored key, not the vault key, so no per-row key exists for
	// them and the scope key cannot derive them either. The authored key rides
	// in every capability precisely so exec can still hand them to the process
	// that needs them — otherwise an agent could store a credential and then
	// watch its own service start without it.
	if authKey, ok := rowKeys[vault.CapAuthoredKeyName]; ok {
		infos, lerr := st.ListEnvVars(ctx, scope)
		if lerr != nil {
			return nil, internalErr(id, fmt.Errorf("list scope for authored entries: %w", lerr))
		}
		for _, info := range infos {
			if _, done := seen[info.Name]; done {
				continue
			}
			if allowed != nil {
				if _, ok := allowed[info.Name]; !ok {
					continue
				}
			}
			val, verr := st.OpenEnvVarAuthored(ctx, scope, info.Name, authKey)
			if verr != nil {
				continue // not an authored entry, or not this scope's — other paths cover it
			}
			seen[info.Name] = struct{}{}
			values = append(values, ipc.ExecFetchValue{Name: info.Name, Value: val})
		}
	}

	for name, rk := range rowKeys {
		if name == vault.CapScopeKeyName || name == vault.CapAuthoredKeyName {
			continue
		}
		if _, done := seen[name]; done {
			continue
		}
		if allowed != nil {
			if _, ok := allowed[name]; !ok {
				continue
			}
		}
		val, verr := st.OpenEnvVarWithRowKey(ctx, scope, name, rk)
		if verr != nil {
			if errors.Is(verr, vault.ErrNotFound) {
				continue // captured var since deleted — skip
			}
			return nil, internalErr(id, fmt.Errorf("decrypt %q via capability: %w", name, verr))
		}
		values = append(values, ipc.ExecFetchValue{Name: name, Value: val})
	}
	return values, nil
}

// execValuesFromVaultKey injects env-var values using the in-memory vault key —
// the path for ad-hoc exec and for a trusted record that predates exec
// capabilities. Requires an unlocked vault (the caller gates that). With
// wildcard set, or an empty allow list, every var in scope is injected;
// otherwise only the allowlisted names.
func (d *Daemon) execValuesFromVaultKey(ctx context.Context, id string, st *vault.Store, scope vault.Scope, allow []string, wildcard bool) ([]ipc.ExecFetchValue, *ipc.Envelope) {
	infos, err := st.ListEnvVars(ctx, scope)
	if err != nil {
		return nil, mapVaultErr(id, err)
	}
	allowSet := make(map[string]bool, len(allow))
	for _, n := range allow {
		allowSet[n] = true
	}
	values := make([]ipc.ExecFetchValue, 0, len(infos))
	for _, m := range infos {
		if !wildcard && len(allow) > 0 && !allowSet[m.Name] {
			continue
		}
		got, gerr := st.GetEnvVar(ctx, scope, m.Name)
		if gerr != nil {
			return nil, mapVaultErr(id, gerr)
		}
		values = append(values, ipc.ExecFetchValue{Name: got.Name, Value: got.Value})
	}
	return values, nil
}

// trustDenyMessage renders why exec was blocked, matching the CLI's
// historical wording so user-facing messages don't drift.
func trustDenyMessage(path string, status trust.VerifyStatus) string {
	switch status {
	case trust.VerifyChanged:
		// Include the diff hint so spec §1a notice reaches the user without
		// breaking the "Run: byn trust <path>" recovery command in the CLI.
		return path + " has CHANGED since you trusted it" +
			" — run `byn trust diff " + path + "` to see what changed"
	case trust.VerifyStale:
		return path + " predates tamper-protection"
	case trust.VerifyTampered:
		return path + " FAILED its tamper check (forged or copied from another machine)"
	default:
		return path + " is untrusted"
	}
}

// missingAllowlisted returns the names a .byn allowlists that the vault has no
// value for.
//
// These used to vanish silently: injection skips a name with no value, the
// service starts normally, and it dies at first use of the variable — often
// mid-test, with nothing connecting the crash back to byn. Reporting the names
// at exec time turns a delayed, mystifying failure into an immediate one that
// says which variable and which file.
//
// A wildcard allowlist has nothing to compare against — it asks for whatever
// exists — so it can never be short.
func missingAllowlisted(allow, optional []string, wildcard bool, values []ipc.ExecFetchValue) []string {
	if wildcard || len(allow) == 0 {
		return nil
	}
	got := make(map[string]struct{}, len(values))
	for _, v := range values {
		got[v.Name] = struct{}{}
	}
	// Names the author has said the program can run without. Warning about
	// those made the check fire on every healthy launch, which is how a warning
	// stops being read.
	skip := make(map[string]struct{}, len(optional))
	for _, n := range optional {
		skip[n] = struct{}{}
	}
	var missing []string
	for _, name := range allow {
		if name == "*" {
			continue
		}
		if _, ok := skip[name]; ok {
			continue
		}
		if _, ok := got[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}
