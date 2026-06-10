package daemon

import (
	"context"
	"os"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// handleExecFetch authorizes a `byn exec` and returns the values to
// inject, enforcing the trusted .byn's [exec] env allowlist SERVER-side:
// the daemon reads, trust-verifies (fp-MAC + vk-MAC at use-time), and
// parses the .byn itself, so a compromised CLI cannot widen the list
// (NU-1; spec §4.4). The trusted .byn IS the authorization — no password
// and no per-action gate. Ad-hoc exec (Path="") keeps pre-NU semantics:
// whole-scope injection, vault must be unlocked for values to flow.
// Scope project/env remain client-chosen, as with every data-plane op;
// the gate's job is preventing the FILE from widening the injection set,
// and the vk-MAC binds the record to its vault.
func (d *Daemon) handleExecFetch(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ExecFetchReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		return errEnv
	}

	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
	canon := ""
	if req.Path != "" {
		canon = trust.Canonicalize(req.Path)
	}
	auditExec := func(resp *ipc.Envelope) {
		outcome, code := outcomeFor(resp)
		d.auditEmit(ctx, vaultName, audit.Event{
			Op: "exec", Outcome: outcome, BynPath: canon,
			Command: req.Command, ErrorCode: code,
		})
	}

	// Early lock check: exec ALWAYS needs an unlocked vault.
	// Even for zero-value injections, values must never flow from a
	// locked vault — this is STRICTER than the old CLI path (which could
	// proceed with a zero-value injection while locked).
	if st.IsLocked() {
		le := ipc.NewError(env.ID, ipc.CodeLocked, "vault is locked", "byn unlock")
		auditExec(le)
		return le
	}

	// Per-action auth gate for ad-hoc exec (Path=""). Trusted-.byn exec
	// (Path!="") stays credential-free — the .byn IS the authorization
	// (spec §4.4). Ad-hoc exec hands out the whole scope, so it must be
	// gated the same way as `get` when [security] per_action_auth is on.
	if d.perActionAuth() && req.Path == "" {
		if len(req.Password) == 0 && len(req.PresenceToken) == 0 {
			// No credentials supplied: emit the exec-specific message so the
			// user understands that running from a trusted .byn is an alternative.
			le := ipc.NewError(env.ID, ipc.CodeAuthRequired,
				"ad-hoc exec requires authorization ([security] per_action_auth)",
				"run from a directory with a trusted .byn, or supply the password")
			auditExec(le)
			return le
		}
		// Credentials present: route through the standard gate (verifies
		// password / presence token, handles rate-limiting). If it fails,
		// return its envelope (audited). The gate is a no-op if the flag is
		// off, but we already checked it above.
		if le := d.authorizeAction(ctx, env.ID, vaultName, st, req.Password, req.PresenceToken); le != nil {
			auditExec(le)
			return le
		}
	}

	var allow []string
	wildcard, noneDeclared := false, false
	if req.Path != "" {
		body, rerr := os.ReadFile(canon) // #nosec G304 -- user-named; daemon runs as the same user
		if rerr != nil {
			le := ipc.NewError(env.ID, ipc.CodeTrustDenied,
				canon+" is untrusted (unreadable)", "byn trust "+canon)
			auditExec(le)
			return le
		}
		// Use-time trust gate. fp-MAC always; vk-MAC whenever values can
		// flow (vault unlocked). Fail CLOSED if the vk key can't derive.
		var vkKey []byte
		vkKey, derr := st.DeriveSubkey(trust.VKMACKeyInfo)
		if derr != nil {
			resp := mapVaultErr(env.ID, derr)
			auditExec(resp)
			return resp
		}
		defer zeroBytes(vkKey)

		status, _, verr := trust.Verify(d.cfg.Dir, canon, trust.Hash(body), d.fpMACKey, vkKey)
		if verr != nil {
			ie := internalErr(env.ID, verr)
			auditExec(ie)
			return ie
		}
		if status != trust.VerifyTrusted {
			le := ipc.NewError(env.ID, ipc.CodeTrustDenied,
				trustDenyMessage(canon, status), "byn trust "+canon)
			auditExec(le)
			return le
		}
		f, perr := bynfile.Parse(body)
		if perr != nil {
			be := badRequest(env.ID, perr)
			auditExec(be)
			return be
		}
		allow = []string(f.Exec.Env)
		wildcard = f.AllowsAll()
		noneDeclared = !wildcard && len(allow) == 0
	}

	infos, err := st.ListEnvVars(ctx, scope)
	if err != nil {
		resp := mapVaultErr(env.ID, err)
		auditExec(resp)
		return resp
	}
	allowSet := make(map[string]bool, len(allow))
	for _, n := range allow {
		allowSet[n] = true
	}
	values := make([]ipc.ExecFetchValue, 0, len(infos))
	for _, m := range infos {
		if req.Path != "" && !wildcard && !allowSet[m.Name] {
			continue
		}
		got, gerr := st.GetEnvVar(ctx, scope, m.Name)
		if gerr != nil {
			resp := mapVaultErr(env.ID, gerr)
			auditExec(resp)
			return resp
		}
		values = append(values, ipc.ExecFetchValue{Name: got.Name, Value: got.Value})
	}
	d.touchVault(req.Scope.Vault)
	resp, rerr := ipc.NewResponse(env.ID, ipc.ExecFetchResp{
		Values: values, Wildcard: wildcard, NoneDeclared: noneDeclared,
	})
	if rerr != nil {
		ie := internalErr(env.ID, rerr)
		auditExec(ie)
		return ie
	}
	auditExec(resp)
	return resp
}

// trustDenyMessage renders why exec was blocked, matching the CLI's
// historical wording so user-facing messages don't drift.
func trustDenyMessage(path string, status trust.VerifyStatus) string {
	switch status {
	case trust.VerifyChanged:
		return path + " has CHANGED since you trusted it"
	case trust.VerifyStale:
		return path + " predates tamper-protection"
	case trust.VerifyTampered:
		return path + " FAILED its tamper check (forged or copied from another machine)"
	default:
		return path + " is untrusted"
	}
}
