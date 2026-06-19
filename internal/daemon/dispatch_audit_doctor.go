package daemon

import (
	"context"
	"fmt"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// ---- Audit -------------------------------------------------------------

// handleAuditTail returns the most recent events from the named
// vault's audit log. Allowed on a locked vault — the log is metadata,
// not secret content. Vault must exist on disk; missing → NotInit.
func (d *Daemon) handleAuditTail(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.AuditTailReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	name := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	if err := vault.ValidateVaultName(name); err != nil {
		return ipc.NewError(env.ID, ipc.CodeBadName, err.Error(), "")
	}
	entry, err := d.openVault(ctx, name)
	if err != nil {
		return ipc.NewError(env.ID, ipc.CodeNotInit,
			fmt.Sprintf("vault %q: %v", name, err),
			"check `byn vault list`")
	}
	events, err := entry.auditor.Tail(ctx, req.Lines)
	if err != nil {
		return internalErr(env.ID, err)
	}
	wire := make([]ipc.AuditEvent, len(events))
	for i, e := range events {
		wire[i] = auditToWire(e)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.AuditTailResp{Events: wire})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handleAuditVerify re-walks the HMAC chain end-to-end and reports
// whether the log is intact. Locked vault is fine (HMAC seed lives in
// the unencrypted meta table; audit chain doesn't require vault key).
func (d *Daemon) handleAuditVerify(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.AuditVerifyReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	name := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	if err := vault.ValidateVaultName(name); err != nil {
		return ipc.NewError(env.ID, ipc.CodeBadName, err.Error(), "")
	}
	entry, err := d.openVault(ctx, name)
	if err != nil {
		return ipc.NewError(env.ID, ipc.CodeNotInit,
			fmt.Sprintf("vault %q: %v", name, err),
			"check `byn vault list`")
	}
	bad, total, _, vErr := entry.auditor.VerifyChain(ctx)
	if vErr != nil {
		return internalErr(env.ID, vErr)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.AuditVerifyResp{
		Total:    total,
		BadIndex: bad,
	})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

func auditToWire(e audit.Event) ipc.AuditEvent {
	return ipc.AuditEvent{
		TS:            e.TS,
		VaultID:       e.VaultID,
		VaultName:     e.VaultName,
		Project:       e.Project,
		Env:           e.Env,
		Kind:          e.Kind,
		EntryName:     e.EntryName,
		BynPath:       e.BynPath,
		Command:       e.Command,
		Op:            e.Op,
		Outcome:       e.Outcome,
		CallerUID:     e.CallerUID,
		CallerPID:     e.CallerPID,
		CallerComm:    e.CallerComm,
		CallerPComm:   e.CallerPComm,
		CallerSurface: e.CallerSurface,
		ErrorCode:     e.ErrorCode,
		HMACChain:     e.HMACChain,
	}
}

// ---- Doctor ------------------------------------------------------------

// handleDoctor runs a structured battery of self-checks across the
// daemon and every vault on disk (not just open ones), so a brand-new
// `byn doctor` invocation surfaces problems even before the user
// unlocks anything.
func (d *Daemon) handleDoctor(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	checks := []ipc.DoctorCheck{
		{Name: "daemon", Severity: "ok", Detail: fmt.Sprintf("running (version %s)", d.cfg.Version)},
	}

	// List vaults on disk.
	names, lErr := d.allVaultsOnDisk()
	switch {
	case lErr != nil:
		checks = append(checks, ipc.DoctorCheck{
			Name: "vaults.list", Severity: "fail",
			Detail: lErr.Error(),
		})
	case len(names) == 0:
		checks = append(checks, ipc.DoctorCheck{
			Name: "vaults.list", Severity: "warn",
			Detail: "no vaults initialized — run `byn init`",
		})
	default:
		checks = append(checks, ipc.DoctorCheck{
			Name: "vaults.list", Severity: "ok",
			Detail: fmt.Sprintf("%d on disk: %v", len(names), names),
		})
	}

	for _, name := range names {
		entry, oErr := d.openVault(ctx, name)
		if oErr != nil {
			checks = append(checks, ipc.DoctorCheck{
				Name: "vault[" + name + "].open", Severity: "fail",
				Detail: oErr.Error(),
			})
			continue
		}
		// vault.Open verifies the schema-version and the meta.json
		// fingerprint internally; if we got here, both are intact.
		checks = append(checks, ipc.DoctorCheck{
			Name: "vault[" + name + "].open", Severity: "ok",
			Detail: "schema + fingerprint ok",
		})
		// Audit chain.
		bad, total, _, vErr := entry.auditor.VerifyChain(ctx)
		switch {
		case vErr != nil:
			checks = append(checks, ipc.DoctorCheck{
				Name: "vault[" + name + "].audit", Severity: "fail",
				Detail: vErr.Error(),
			})
		case bad >= 0:
			checks = append(checks, ipc.DoctorCheck{
				Name: "vault[" + name + "].audit", Severity: "fail",
				Detail: fmt.Sprintf("chain broken at event #%d", bad),
			})
		default:
			checks = append(checks, ipc.DoctorCheck{
				Name: "vault[" + name + "].audit", Severity: "ok",
				Detail: fmt.Sprintf("%d events, chain intact", total),
			})
		}
	}

	resp, err := ipc.NewResponse(env.ID, ipc.DoctorResp{Checks: checks})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}
