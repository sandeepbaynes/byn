package daemon

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

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
		// Not one of the IPC ops: raising is something the daemon does on the
		// caller's behalf, and logging it as "approval.list" would misname the
		// event for whoever reads the log back.
		Op:      "approval.raise",
		Outcome: audit.OutcomePending, // the question was put; nothing was refused
		BynPath: canon,
		Command: "approval raised " + pending.ID + ": " + strings.Join(summary, "; "),
	})

	return ipc.NewErrorWithDetails(id, ipc.CodeApprovalPending,
		fmt.Sprintf("%s asks for more than it was granted (%s) — approval %s is waiting",
			canon, strings.Join(summary, "; "), pending.ID),
		"approve it with: byn approve "+pending.ID,
		approvalDetails(pending, ""))
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

// actionApprovalKey derives everything that identifies one "may I run this
// command here" question: the display form, the summary a person reads, and the
// fingerprint that decides whether two askings are the same question.
//
// One function so that recognising an existing answer and raising a new request
// cannot drift apart. If they computed the fingerprint differently, approving
// would appear to work and change nothing — the caller would be told it was
// granted and be asked again on the very next attempt, forever.
func actionApprovalKey(canon, command string, resolvedArgv []string) (cmd string, summary []string, fingerprint string) {
	cmd = strings.Join(resolvedArgv, " ")
	if cmd == "" {
		cmd = command
	}
	if len(cmd) > 200 { // the card is read by a person; keep it legible
		cmd = cmd[:200] + "…"
	}
	summary = []string{"runs " + cmd}
	return cmd, summary, fingerprintOf(canon, summary)
}

// actionApproved reports whether someone has already approved this exact
// command on this exact .byn, and the grant has not lapsed.
//
// Best-effort: an unreadable queue means "not approved", so the caller is asked
// again rather than let through on a store byn could not read.
func (d *Daemon) actionApproved(canon, command string, resolvedArgv []string) bool {
	_, ok := d.actionApprovedUntil(canon, command, resolvedArgv)
	return ok
}

// actionApprovedUntil is actionApproved plus when the grant lapses, so a caller
// can be told how long it has rather than discovering the end by being stopped.
func (d *Daemon) actionApprovedUntil(canon, command string, resolvedArgv []string) (int64, bool) {
	if d.approvals == nil {
		return 0, false
	}
	_, _, fingerprint := actionApprovalKey(canon, command, resolvedArgv)
	granted, until, err := d.approvals.ActionGrantedUntil(canon, fingerprint)
	if err != nil || !granted {
		return 0, false
	}
	return until.Unix(), true
}

// raiseActionApproval records that a caller wants to run a command the trusted
// .byn does not pin, and returns the error it sees.
//
// This is the gate agents meet most often. It used to end at "auth: not a
// terminal", which is not something a caller without a terminal can act on —
// the run stopped and a person had to add the command to [exec] actions and
// re-trust. Turning it into a decision keeps the same authority boundary (the
// command still does not run until a human agrees) while removing the dead end.
func (d *Daemon) raiseActionApproval(ctx context.Context, id, canon, vaultName string,
	req ipc.ExecFetchReq, resolvedArgv []string) *ipc.Envelope {

	cmd, summary, fingerprint := actionApprovalKey(canon, req.Command, resolvedArgv)

	// Already refused? Say so and stop, rather than quietly raising a new id.
	//
	// Re-asking a person who just said no is how approval fatigue starts, and
	// the caller learns nothing from a fresh id it did not earn. Telling it WHEN
	// it was refused, and why if a reason was given, is what lets it decide
	// between fixing the cause and stopping. --force-ask re-raises deliberately.
	if denial, refused := d.approvals.LastDenial(canon, fingerprint); refused && !req.ForceAsk {
		msg := fmt.Sprintf("%s was refused at %s", cmd, denial.DecidedAt.Format(time.RFC3339))
		if denial.DecidedReason != "" {
			msg += ": " + denial.DecidedReason
		}
		return ipc.NewErrorWithDetails(id, ipc.CodeTrustDenied, msg,
			"pin it in [exec] actions and re-trust, or ask again with: byn exec --force-ask",
			map[string]string{
				"denied_at": strconv.FormatInt(denial.DecidedAt.Unix(), 10),
				"reason":    denial.DecidedReason,
				"byn":       canon,
				"command":   cmd,
			})
	}

	pending, err := d.approvals.Enqueue(approval.Request{
		Kind:        approval.KindActionUnpinned,
		Vault:       vaultName,
		Subject:     canon,
		Fingerprint: fingerprint,
		Summary:     summary,
		Requestor:   requestorOf(req),
	})
	switch {
	case errors.Is(err, approval.ErrOnHold):
		return ipc.NewError(id, ipc.CodeTrustDenied,
			fmt.Sprintf("%s is not pinned in %s and that request was already refused", cmd, canon),
			"pin it in [exec] actions and re-trust, or wait for the hold to lapse")
	case errors.Is(err, approval.ErrRateLimited):
		return ipc.NewError(id, ipc.CodeTrustDenied,
			fmt.Sprintf("%s has too many approvals already waiting", canon),
			"answer the pending requests first: byn approve")
	case err != nil:
		return internalErr(id, fmt.Errorf("queue approval: %w", err))
	}

	d.auditEmit(ctx, vaultName, audit.Event{
		Op: "approval.raise", Outcome: audit.OutcomePending, BynPath: canon,
		Command: "approval raised " + pending.ID + ": " + strings.Join(summary, "; "),
	})
	return ipc.NewErrorWithDetails(id, ipc.CodeApprovalPending,
		fmt.Sprintf("%s is not pinned in %s [exec] actions — approval %s is waiting",
			cmd, canon, pending.ID),
		"approve it with: byn approve "+pending.ID+
			", or pin it in [exec] actions and re-trust",
		approvalDetails(pending, cmd))
}

// approvalDetails is the machine-readable half of a paused command: everything
// a caller needs to hand the request to a person, or to wait for it, without
// reading the English sentence next to it.
func approvalDetails(pending approval.Request, command string) map[string]string {
	d := map[string]string{
		"approval_id": pending.ID,
		"kind":        string(pending.Kind),
		"byn":         pending.Subject,
		"expires_at":  strconv.FormatInt(pending.ExpiresAt.Unix(), 10),
	}
	if command != "" {
		d["command"] = command
	}
	if pending.Vault != "" {
		d["vault"] = pending.Vault
	}
	return d
}

// grantExpiryFor reports when a standing approval covering this command lapses,
// or 0 when the .byn itself is what allows it.
//
// Asked after the fact rather than threaded through the authorization path: the
// answer is only for display, and a command allowed by the file has no expiry
// to report.
func (d *Daemon) grantExpiryFor(req ipc.ExecFetchReq, resolvedArgv []string) int64 {
	if req.Path == "" {
		return 0
	}
	until, ok := d.actionApprovedUntil(trust.Canonicalize(req.Path), req.Command, resolvedArgv)
	if !ok {
		return 0
	}
	return until
}
