package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sandeepbaynes/byn/internal/approval"
	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

// raiseTrustApproval records that a .byn is asking for more authority than it
// was granted, and returns the error the caller sees.
//
// The error is the point of the exercise: it names a request id, so a caller
// that cannot answer a prompt still has somewhere to go. Previously this path
// ended at "run byn trust", which an agent cannot do — and because trust is
// per-project, one agent's unanswerable prompt stalled every other agent
// working there.
func (d *Daemon) raiseTrustApproval(ctx context.Context, id, canon, vaultName string,
	req ipc.ExecFetchReq, delta trust.Delta) *ipc.Envelope {

	summary := make([]string, 0, len(delta.Widenings))
	for _, w := range delta.Widenings {
		summary = append(summary, w.Detail)
	}

	pending, err := d.approvals.Enqueue(approval.Request{
		Kind:        approval.KindTrustWidening,
		Vault:       vaultName,
		Subject:     canon,
		Fingerprint: fingerprintOf(canon, summary),
		Summary:     summary,
		HighRisk:    delta.HighRisk(),
		Requestor:   requestorOf(req),
	})
	switch {
	case errors.Is(err, approval.ErrOnHold):
		return ipc.NewError(id, ipc.CodeTrustDenied,
			fmt.Sprintf("%s asks for more than it was granted, and that request was already refused: %s",
				canon, strings.Join(summary, "; ")),
			"this request is on hold after repeated denials; change the .byn or wait for the hold to lapse")
	case errors.Is(err, approval.ErrRateLimited):
		return ipc.NewError(id, ipc.CodeTrustDenied,
			fmt.Sprintf("%s has too many approvals already waiting", canon),
			"answer the pending requests first: byn approve")
	case err != nil:
		return internalErr(id, fmt.Errorf("queue approval: %w", err))
	}

	// A request is a security event in its own right: it records that something
	// asked for authority it did not have, whether or not anyone ever answers.
	d.auditEmit(ctx, vaultName, audit.Event{
		Op:      string(ipc.OpApprovalList), // "approval.*" family
		Outcome: audit.OutcomeDenied,        // nothing was granted by asking
		BynPath: canon,
		Command: "approval raised " + pending.ID + ": " + strings.Join(summary, "; "),
	})

	return ipc.NewError(id, ipc.CodeApprovalPending,
		fmt.Sprintf("%s asks for more than it was granted (%s) — approval %s is waiting",
			canon, strings.Join(summary, "; "), pending.ID),
		"approve it with: byn approve "+pending.ID)
}

// fingerprintOf identifies a question by what it asks for, so the same request
// coming from a retry loop collapses onto one card rather than a hundred.
func fingerprintOf(subject string, summary []string) string {
	return trust.Policy{
		Project:   subject,
		EnvGrants: summary,
	}.Hash()
}

func requestorOf(req ipc.ExecFetchReq) approval.Requestor {
	return approval.Requestor{Exe: req.Command}
}
