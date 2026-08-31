package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sandeepbaynes/byn/internal/approval"
	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// maxGrantWindow bounds how long an owner can let one command run free without
// being asked again. A day is already generous for something the durable answer
// to is pinning it in [exec] actions.
const maxGrantWindow = 24 * time.Hour

func approvalEntry(r approval.Request) ipc.ApprovalEntry {
	return ipc.ApprovalEntry{
		ID: r.ID, Kind: string(r.Kind), Vault: r.Vault, Subject: r.Subject,
		Summary: r.Summary, HighRisk: r.HighRisk, Status: string(r.Status),
		CreatedAt: r.CreatedAt.Unix(), ExpiresAt: r.ExpiresAt.Unix(),
		Repeats: r.Repeats, DecidedVia: r.DecidedVia,
		DecidedReason: r.DecidedReason,
		DecidedAt:     decidedUnix(r.DecidedAt),
		GrantedUntil:  decidedUnix(r.GrantedUntil),
		Reason:        r.Reason,
		NeededBy:      decidedUnix(r.NeededBy),
		Late:          r.Late,
		Anyone:        r.Anyone,
		Requestor: ipc.ApprovalActor{
			PID: r.Requestor.PID, Exe: r.Requestor.Exe, Cwd: r.Requestor.Cwd,
			User: r.Requestor.User, Agent: r.Requestor.Agent,
			AgentPID: r.Requestor.AgentPID, Attended: r.Requestor.Attended,
			Display: r.Requestor.String(),
		},
	}
}

// decidedUnix renders a decision time, or 0 when there has not been one.
// time.Time's zero value is a large negative Unix second, which would read as a
// real timestamp in 1754 to anything consuming the JSON.
func decidedUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// handleApprovalList returns the queue. Listing needs no credentials: the
// entries describe what is being ASKED for, never a secret, and someone has to
// be able to see what is waiting before they can decide it.
func (d *Daemon) handleApprovalList(env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ApprovalListReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	list, err := d.approvals.List(approval.Status(req.Status))
	if err != nil {
		return internalErr(env.ID, err)
	}
	out := make([]ipc.ApprovalEntry, 0, len(list))
	for _, r := range list {
		out = append(out, approvalEntry(r))
	}
	resp, rerr := ipc.NewResponse(env.ID, ipc.ApprovalListResp{Entries: out})
	if rerr != nil {
		return internalErr(env.ID, rerr)
	}
	return resp
}

// handleApprovalDecide answers a queued decision.
//
// Approving a trust widening grants authority, so it demands the master
// password exactly as `byn trust` does. That is deliberate: the queue exists so
// an agent is not BLOCKED waiting for consent, not so consent becomes something
// an agent can give itself. Denying asks for nothing, so it needs no password —
// making refusal the cheaper action.
func (d *Daemon) handleApprovalDecide(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ApprovalDecideReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	pending, err := d.approvals.Get(req.ID)
	if errors.Is(err, approval.ErrNotFound) {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			"no approval with id "+req.ID, "list what is waiting: byn approve")
	}
	if err != nil {
		return internalErr(env.ID, err)
	}

	// Revoking needs no password, for the same reason denying does not: it can
	// only ever remove capability. Handled before the approve branch so it is
	// never mistaken for a decision being made afresh.
	if req.Revoke {
		revoked, rerr := d.approvals.Revoke(req.ID)
		if errors.Is(rerr, approval.ErrNotApproved) {
			return ipc.NewError(env.ID, ipc.CodeBadRequest, rerr.Error(),
				"only an approved request has a grant to take back: byn approve")
		}
		if rerr != nil {
			return internalErr(env.ID, rerr)
		}
		d.auditEmit(ctx, defaultIfEmpty(revoked.Vault, vault.DefaultVaultName), audit.Event{
			Op: "approval.revoke", Outcome: audit.OutcomeOK, BynPath: revoked.Subject,
			Command: "revoked " + revoked.ID + ": " + strings.Join(revoked.Summary, "; "),
		})
		out, rerr2 := ipc.NewResponse(env.ID, ipc.ApprovalDecideResp{Entry: approvalEntry(revoked)})
		if rerr2 != nil {
			return internalErr(env.ID, rerr2)
		}
		return out
	}

	if req.Approve {
		if len(req.Password) == 0 {
			return ipc.NewError(env.ID, ipc.CodeAuthRequired,
				"approving grants authority, so it needs the master password",
				"byn approve "+req.ID)
		}
		vaultName := defaultIfEmpty(pending.Vault, vault.DefaultVaultName)
		st, errEnv := d.storeForVault(env.ID, vaultName)
		if errEnv != nil {
			return errEnv
		}
		// A recorded decision is not the point — the grant is. Marking the
		// request approved without re-granting would leave the .byn exactly as
		// it was, so the next exec would raise the same question again and the
		// caller would never get past it.
		if errEnv := d.applyTrustApproval(ctx, env.ID, vaultName, st, pending, req.Password); errEnv != nil {
			return errEnv
		}
	}

	via := req.Via
	if via == "" {
		via = "terminal"
	}
	// The window the owner chose, when they chose one. Bounded on the way in:
	// a grant length arriving over IPC decides how long something runs without
	// asking again, so an absurd one is refused rather than honoured.
	grantFor := time.Duration(req.GrantForSeconds) * time.Second
	if grantFor < 0 || grantFor > maxGrantWindow {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			fmt.Sprintf("a grant window must be between 0 and %s", maxGrantWindow),
			"byn approve "+req.ID+" --for 30m")
	}
	decide := d.approvals.DecideFor
	if req.Anyone {
		decide = d.approvals.DecideForAnyone
	}
	decided, err := decide(req.ID, req.Approve, via, req.Reason, grantFor)
	if err != nil {
		return internalErr(env.ID, err)
	}
	// The decision is the moment authority changes hands, so it belongs in the
	// log with WHERE it was made — terminal, portal, or phone. An approval
	// nobody can audit is an approval nobody can review after the fact.
	outcome := audit.OutcomeDenied
	if decided.Status == approval.StatusApproved {
		outcome = audit.OutcomeOK
	}
	d.auditEmit(ctx, defaultIfEmpty(pending.Vault, vault.DefaultVaultName), audit.Event{
		Op:      string(ipc.OpApprovalDecide),
		Outcome: outcome,
		BynPath: pending.Subject,
		Command: string(decided.Status) + " via " + decided.DecidedVia + " (" + decided.ID + ")" +
			reasonSuffix(decided.DecidedReason),
	})
	resp, rerr := ipc.NewResponse(env.ID, ipc.ApprovalDecideResp{Entry: approvalEntry(decided)})
	if rerr != nil {
		return internalErr(env.ID, rerr)
	}
	return resp
}

// applyTrustApproval re-grants the .byn a widening request was raised for, so
// approving actually changes what the caller can do. It runs the same
// authorization and record-writing path `byn trust` does, which keeps one
// definition of what a grant means rather than a second, weaker one reachable
// through the queue.
func (d *Daemon) applyTrustApproval(ctx context.Context, id, vaultName string,
	st *vault.Store, pending approval.Request, password []byte) *ipc.Envelope {

	if pending.Kind != approval.KindTrustWidening {
		return nil
	}
	vkKey, le := d.authorizeTrustGrant(ctx, id, vaultName, st, password, nil)
	if le != nil {
		return le
	}
	defer zeroBytes(vkKey)

	body, _, rerr := readBynFile(pending.Subject)
	if rerr != nil {
		return ipc.NewError(id, ipc.CodeBadRequest,
			fmt.Sprintf("re-reading %s: %v", pending.Subject, rerr),
			"the file changed or was removed since the request was raised")
	}
	if _, _, _, _, terr := d.putTrustRecordWithKey(
		ctx, st, vaultName, pending.Subject, body, vkKey, password); terr != nil {
		return ipc.NewError(id, ipc.CodeBadRequest,
			fmt.Sprintf("granting %s: %v", pending.Subject, terr),
			"fix the .byn and raise the request again")
	}
	return nil
}

// reasonSuffix renders a decision's reason for the audit line, or nothing.
func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	if len(reason) > 200 { // the log is read by people; keep the line legible
		reason = reason[:200] + "…"
	}
	return ": " + reason
}
