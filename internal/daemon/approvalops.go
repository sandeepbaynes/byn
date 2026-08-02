package daemon

import (
	"context"
	"errors"

	"github.com/sandeepbaynes/byn/internal/approval"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

func approvalEntry(r approval.Request) ipc.ApprovalEntry {
	return ipc.ApprovalEntry{
		ID: r.ID, Kind: string(r.Kind), Vault: r.Vault, Subject: r.Subject,
		Summary: r.Summary, HighRisk: r.HighRisk, Status: string(r.Status),
		CreatedAt: r.CreatedAt.Unix(), ExpiresAt: r.ExpiresAt.Unix(),
		Repeats: r.Repeats, DecidedVia: r.DecidedVia,
	}
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

	if req.Approve {
		if len(req.Password) == 0 {
			return ipc.NewError(env.ID, ipc.CodeAuthRequired,
				"approving grants authority, so it needs the master password",
				"byn approve "+req.ID)
		}
		st, _, errEnv := d.scopeFor(env.ID, ipc.Scope{Vault: pending.Vault})
		if errEnv != nil {
			return errEnv
		}
		if verr := st.VerifyPassword(req.Password); verr != nil {
			return mapVaultErr(env.ID, verr)
		}
	}

	via := req.Via
	if via == "" {
		via = "terminal"
	}
	decided, err := d.approvals.Decide(req.ID, req.Approve, via)
	if err != nil {
		return internalErr(env.ID, err)
	}
	resp, rerr := ipc.NewResponse(env.ID, ipc.ApprovalDecideResp{Entry: approvalEntry(decided)})
	if rerr != nil {
		return internalErr(env.ID, rerr)
	}
	return resp
}
