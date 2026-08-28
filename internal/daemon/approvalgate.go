package daemon

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"path/filepath"
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
		Requestor:   d.requestorOf(ctx, vaultName, req),
		Reason:      requestReason(req.Reason),
		NeededBy:    neededBy(req.WaitSeconds),
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
		Command: "approval raised " + pending.ID + ": " + strings.Join(summary, "; ") + auditReason(pending),
	})

	return ipc.NewErrorWithDetails(id, ipc.CodeApprovalPending,
		fmt.Sprintf("%s asks for more than it was granted (%s) — approval %s is waiting",
			canon, strings.Join(summary, "; "), pending.ID),
		"approve it with: byn approve "+pending.ID+reasonHint(pending),
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

// requestorOf describes who asked, from what the kernel says rather than from
// what the request claims.
//
// It used to record req.Command as the "exe", which was the command being
// requested — the one thing the card already showed. A person looking at
// "runs make dev" could not tell whether their own agent had asked or something
// else in the same project had, and the answer to that changes the decision.
func (d *Daemon) requestorOf(ctx context.Context, vaultName string, req ipc.ExecFetchReq) approval.Requestor {
	ci := callerFrom(ctx)
	r := approval.Requestor{
		PID:      ci.PID,
		Exe:      ci.Comm,
		Cwd:      procCwd(ci.PID),
		Attended: d.callerIsAttended(ctx, vaultName, req.Password, req.PresenceToken),
	}
	if ci.TTYDev != 0 {
		r.TTY = strconv.FormatInt(int64(ci.TTYDev), 10)
	}
	if u, err := user.LookupId(strconv.FormatUint(uint64(ci.UID), 10)); err == nil {
		r.User = u.Username
	}
	// The agent, not the shell: the same identity that decides whether a caller
	// may read back a value it created, so a card and an unattended value never
	// disagree about who "they" are.
	if id := callerIdentityFn(ci.PID); id.ok() {
		r.AgentPID = id.PID
		r.AgentKey = agentKey(id)
		if comm, _ := procInfo(id.PID); comm != "" {
			r.Agent = comm
		}
	}
	if r.Cwd == "" && req.Path != "" {
		// Falling back to the .byn's directory is not the same fact, but it is
		// the same neighbourhood, and it is the one place byn knows the request
		// came from when /proc has already forgotten the caller.
		r.Cwd = filepath.Dir(trust.Canonicalize(req.Path))
	}
	return r
}

// requestReason is the asker's own words, made safe to print.
//
// The text is written by whatever called byn, so it reaches a person's terminal
// as untrusted input: escape sequences in it could repaint the screen around
// the decision they are about to make. Control characters go, the line is
// bounded, and what survives is shown as a claim rather than as a finding.
func requestReason(s string) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\t', '\n', '\r', '\v', '\f':
			// Whitespace becomes whitespace: dropping a newline outright would
			// weld the words on either side of it into one.
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
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
func (d *Daemon) actionApproved(ctx context.Context, canon, command string, resolvedArgv []string) bool {
	_, ok := d.actionApprovedUntil(ctx, canon, command, resolvedArgv)
	return ok
}

// actionApprovedUntil is actionApproved plus when the grant lapses, so a caller
// can be told how long it has rather than discovering the end by being stopped.
func (d *Daemon) actionApprovedUntil(ctx context.Context, canon, command string, resolvedArgv []string) (int64, bool) {
	if d.approvals == nil {
		return 0, false
	}
	_, _, fingerprint := actionApprovalKey(canon, command, resolvedArgv)
	granted, until, err := d.approvals.ActionGrantFor(canon, fingerprint, d.grantUsableBy(ctx))
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
		Requestor:   d.requestorOf(ctx, vaultName, req),
		Reason:      requestReason(req.Reason),
		NeededBy:    neededBy(req.WaitSeconds),
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
		Command: "approval raised " + pending.ID + ": " + strings.Join(summary, "; ") + auditReason(pending),
	})
	return ipc.NewErrorWithDetails(id, ipc.CodeApprovalPending,
		fmt.Sprintf("%s is not pinned in %s [exec] actions — approval %s is waiting",
			cmd, canon, pending.ID),
		"approve it with: byn approve "+pending.ID+
			", or pin it in [exec] actions and re-trust"+reasonHint(pending),
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
func (d *Daemon) grantExpiryFor(ctx context.Context, req ipc.ExecFetchReq, resolvedArgv []string) int64 {
	if req.Path == "" {
		return 0
	}
	until, ok := d.actionApprovedUntil(ctx, trust.Canonicalize(req.Path), req.Command, resolvedArgv)
	if !ok {
		return 0
	}
	return until
}

// reasonHint tells a caller that raised an unexplained request how to explain
// it, and only when it has not.
//
// It is worth saying to the caller rather than only to the approver, because
// the caller is the one that can fix it: re-running with --reason lands on the
// same pending card and fills in the blank, so the person deciding gets the
// answer without anyone having to ask for it.
func reasonHint(pending approval.Request) string {
	if pending.Reason != "" {
		return ""
	}
	return `; if you retry, pass --reason "why you need this" — it reaches the same request`
}

// neededBy turns the caller's own waiting window into a deadline on the record.
//
// Only the caller knows this: an agent that will sit on a request for two
// minutes and one that has gone away are the same row on a list otherwise, and
// they deserve opposite amounts of hurry. A caller that is not waiting says
// nothing, and the request simply has no deadline.
func neededBy(waitSeconds int) time.Time {
	if waitSeconds <= 0 {
		return time.Time{}
	}
	if waitSeconds > int(maxGrantWindow/time.Second) {
		waitSeconds = int(maxGrantWindow / time.Second)
	}
	return time.Now().Add(time.Duration(waitSeconds) * time.Second)
}

// auditReason appends the asker's stated purpose to the logged event, marked as
// theirs. The log is what someone reads months later to reconstruct why
// authority moved, and "why they said they wanted it" is most of that story —
// as long as the log never presents the claim as byn's own finding.
func auditReason(pending approval.Request) string {
	if pending.Reason == "" {
		return ""
	}
	return " (asker's reason: " + pending.Reason + ")"
}

// agentKey renders an identity so it can be stored and compared later without
// a reused pid quietly standing in for the process that asked.
func agentKey(id procRef) string {
	return strconv.Itoa(id.PID) + ":" + strconv.FormatUint(id.Start, 10)
}

// parseAgentKey reverses agentKey. An unparseable key yields an identity that
// matches nothing, which is the safe direction: a grant byn cannot attribute is
// a grant nobody inherits.
func parseAgentKey(k string) (procRef, bool) {
	pidStr, startStr, ok := strings.Cut(k, ":")
	if !ok {
		return procRef{}, false
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return procRef{}, false
	}
	start, err := strconv.ParseUint(startStr, 10, 64)
	if err != nil {
		return procRef{}, false
	}
	ref := procRef{PID: pid, Start: start}
	return ref, ref.ok()
}

// grantUsableBy decides which existing command grants the caller in ctx may use.
//
// The default is the caller that asked, not the project. A grant keyed only on
// the file and the command lets anything running there use it — the owner
// answered "yes, that agent may run this" and byn was reading it as "yes,
// anyone here may". Binding it to the recorded identity keeps the answer the
// size of the question.
//
// Two grants stay usable by anyone: one the owner deliberately widened with
// --anyone, and one raised before byn recorded an identity at all. The second is
// the version-skew case, and refusing those would re-ask for every grant that
// existed before an upgrade — the surest way to teach people to approve without
// reading.
func (d *Daemon) grantUsableBy(ctx context.Context) func(approval.Request) bool {
	pid := callerFrom(ctx).PID
	return func(r approval.Request) bool {
		if r.Anyone || r.Requestor.AgentKey == "" {
			return true
		}
		want, ok := parseAgentKey(r.Requestor.AgentKey)
		if !ok {
			return false
		}
		return sharesAncestryFn(pid, []procRef{want})
	}
}
