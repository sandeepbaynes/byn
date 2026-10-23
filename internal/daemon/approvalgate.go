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
	"github.com/sandeepbaynes/byn/internal/vault"
)

// raiseTrustApproval records that a .byn is asking for more authority than it
// was granted, and returns the error the caller sees.
//
// The error is the point of the exercise: it names a request id, so a caller
// that cannot answer a prompt still has somewhere to go. Previously this path
// ended at "run byn trust", which an agent cannot do — and because trust is
// per-project, one agent's unanswerable prompt stalled every other agent
// working there.
func (d *Daemon) raiseTrustApproval(ctx context.Context, id, canon, vaultName string, scope vault.Scope,
	req ipc.ExecFetchReq, delta trust.Delta) *ipc.Envelope {

	summary := make([]string, 0, len(delta.Widenings))
	for _, w := range delta.Widenings {
		summary = append(summary, w.Detail)
	}

	ticket, watchHash, terr := approval.NewWatchTicket()
	if terr != nil {
		return internalErr(id, terr)
	}
	pending, created, err := d.approvals.Enqueue(approval.Request{
		WatchHash:   watchHash,
		Kind:        approval.KindTrustWidening,
		Vault:       vaultName,
		Project:     scope.Project,
		Env:         scope.Env,
		Subject:     canon,
		Fingerprint: fingerprintOf(vaultName, scope, canon, summary),
		Summary:     summary,
		HighRisk:    delta.HighRisk(),
		Requestor:   d.requestorOf(ctx, vaultName, req),
		Reason:      requestReason(req.Reason),
		NeededBy:    neededBy(req.WaitSeconds),
		AskOnce:     req.AskOnce,
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
		"approve it with: "+approveHint(vaultName, pending.ID)+reasonHint(pending),
		approvalDetails(pending, "", ticketIfCreated(ticket, created)))
}

// fingerprintOf identifies a question by what it asks for, so the same request
// coming from a retry loop collapses onto one card rather than a hundred.
//
// The vault is part of the question. The same .byn and command run against a
// different vault reach different secrets, and an approval is proven with that
// vault's password — so a grant in one vault must never be recognised as an
// answer in another, or anyone could make a vault of their own, approve there,
// and run the command against the vault the project actually uses.
//
// The scope is in it for the same reason: a grant for one project's values
// says nothing about another's, and --env picks the env for a .byn that pins
// none, so two runs of the same command can reach different secrets.
func fingerprintOf(vaultName string, scope vault.Scope, subject string, summary []string) string {
	return trust.Policy{
		Vault:     defaultIfEmpty(vaultName, vault.DefaultVaultName),
		Project:   subject,
		Env:       scopeLabel(scope),
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
	// The process that asked, pinned across pid reuse. A CLI that waits on
	// this card and retries is this process, whatever happens to its parents
	// in the meantime.
	if self := procSelfRef(ci.PID); self.ok() {
		r.ProcKey = agentKey(self)
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
func actionApprovalKey(vaultName string, scope vault.Scope, canon, command string, resolvedArgv []string) (cmd string, summary []string, fingerprint string) {
	cmd = strings.Join(resolvedArgv, " ")
	if cmd == "" {
		cmd = command
	}
	if len(cmd) > 200 { // the card is read by a person; keep it legible
		cmd = cmd[:200] + "…"
	}
	summary = []string{"runs " + cmd}
	return cmd, summary, fingerprintOf(vaultName, scope, canon, summary)
}

// actionApproved reports whether someone has already approved this exact
// command on this exact .byn in this vault, and the grant has not lapsed.
//
// Best-effort: an unreadable queue means "not approved", so the caller is asked
// again rather than let through on a store byn could not read.
func (d *Daemon) actionApproved(ctx context.Context, vaultName string, scope vault.Scope, canon, command string, resolvedArgv []string) bool {
	_, ok := d.actionApprovedUntil(ctx, vaultName, scope, canon, command, resolvedArgv)
	return ok
}

// actionApprovedUntil is actionApproved plus when the grant lapses, so a caller
// can be told how long it has rather than discovering the end by being stopped.
func (d *Daemon) actionApprovedUntil(ctx context.Context, vaultName string, scope vault.Scope, canon, command string, resolvedArgv []string) (int64, bool) {
	if d.approvals == nil {
		return 0, false
	}
	_, _, fingerprint := actionApprovalKey(vaultName, scope, canon, command, resolvedArgv)
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
func (d *Daemon) raiseActionApproval(ctx context.Context, id, canon, vaultName string, scope vault.Scope,
	req ipc.ExecFetchReq, resolvedArgv []string, gets execGets) *ipc.Envelope {

	cmd, summary, fingerprint := actionApprovalKey(vaultName, scope, canon, req.Command, resolvedArgv)

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

	ticket, watchHash, terr := approval.NewWatchTicket()
	if terr != nil {
		return internalErr(id, terr)
	}
	pending, created, err := d.approvals.Enqueue(approval.Request{
		WatchHash:   watchHash,
		Kind:        approval.KindActionUnpinned,
		Vault:       vaultName,
		Project:     scope.Project,
		Env:         scope.Env,
		Subject:     canon,
		Fingerprint: fingerprint,
		Summary:     summary,
		// What the command receives if approved, resolved now from the .byn
		// so the card can say it. The run resolves it again from the file;
		// a file that later asks for more raises a widening of its own.
		Gets:      gets.Names,
		GetsAll:   gets.All,
		Requestor: d.requestorOf(ctx, vaultName, req),
		Reason:    requestReason(req.Reason),
		NeededBy:  neededBy(req.WaitSeconds),
		AskOnce:   req.AskOnce,
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
		"approve it with: "+approveHint(vaultName, pending.ID)+
			", or pin it in [exec] actions and re-trust"+reasonHint(pending),
		approvalDetails(pending, cmd, ticketIfCreated(ticket, created)))
}

// approvalDetails is the machine-readable half of a paused command: everything
// a caller needs to hand the request to a person, or to wait for it, without
// reading the English sentence next to it.
// ticketIfCreated returns the watch ticket only when this call actually raised
// the request.
//
// A retry, or a second agent asking the same thing, coalesces onto the card
// already waiting — and must not be handed the channel belonging to whoever
// asked first. Without this, any process able to guess what another agent would
// ask for could obtain its ticket by asking for the same thing, and then answer
// for it or withdraw its request.
func ticketIfCreated(ticket string, created bool) string {
	if !created {
		return ""
	}
	return ticket
}

func approvalDetails(pending approval.Request, command, watchTicket string) map[string]string {
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
	// The rest of what a yes reaches: a caller handing the request to a
	// person, or deciding whether to wait, should not have to parse the
	// English for it.
	if pending.Project != "" {
		d["project"] = pending.Project
	}
	if pending.Env != "" {
		d["env"] = pending.Env
	}
	switch {
	case pending.GetsAll:
		d["gets"] = "*"
	case len(pending.Gets) > 0:
		d["gets"] = strings.Join(pending.Gets, ",")
	}
	if pending.Beside != "" {
		d["beside"] = pending.Beside
	}
	// Handed over exactly here and nowhere else. There is no op that returns a
	// ticket for an existing request, deliberately: an agent that dropped it
	// cannot ask for it back, because a way to re-request one would be a way for
	// anything else to request it too.
	if watchTicket != "" {
		d["watch_ticket"] = watchTicket
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
	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
	if len(req.Vars) > 0 {
		// An ad hoc run is on a grant by definition; say when it lapses.
		vars, err := adhocVars(req.Vars)
		subject := d.adhocSubject(ctx, req)
		if err != nil || subject == "" || d.approvals == nil {
			return 0
		}
		_, _, fingerprint := adhocApprovalKey(vaultName, scopeOf(req.Scope), subject, req.Argv, vars)
		granted, until, gerr := d.approvals.ActionGrantFor(subject, fingerprint, d.grantUsableBy(ctx))
		if gerr != nil || !granted {
			return 0
		}
		return until.Unix()
	}
	if req.Path == "" {
		return 0
	}
	until, ok := d.actionApprovedUntil(ctx, vaultName, scopeOf(req.Scope),
		trust.Canonicalize(req.Path), req.Command, resolvedArgv)
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
//
// The process that raised the request may always use its grant. It is the
// most exact reading of "whoever asked" there is, and it is the one caller the
// ancestry check can wrongly refuse: a CLI that waits on its card can lose
// the shell between itself and the agent while it waits (a harness timeout or
// a backgrounded tool call), be reparented to init, and then be unable to
// prove the agent identity recorded seconds earlier. It re-raised a fresh card
// with no identity at all, every retry, and the grant it had was never used.
func (d *Daemon) grantUsableBy(ctx context.Context) func(approval.Request) bool {
	pid := callerFrom(ctx).PID
	return func(r approval.Request) bool {
		if r.Anyone || r.Requestor.AgentKey == "" {
			return true
		}
		if self, ok := parseAgentKey(r.Requestor.ProcKey); ok && procSelfRef(pid) == self {
			return true
		}
		want, ok := parseAgentKey(r.Requestor.AgentKey)
		if !ok {
			return false
		}
		return sharesAncestryFn(pid, []procRef{want})
	}
}

// procSelfRef pins a live process as (pid, start time), or returns a reference
// that matches nothing when the platform cannot supply a start time.
func procSelfRef(pid int) procRef {
	if pid <= 0 {
		return procRef{}
	}
	start, ok := procStartTime(pid)
	if !ok {
		return procRef{}
	}
	return procRef{PID: pid, Start: start}
}

// consumeOnceGrant spends a single-use grant for this command, if that is what
// authorized it. Reports whether one was spent, for the audit line.
//
// Best-effort: a queue byn cannot write is not a reason to refuse a command it
// has already decided to allow. The grant outliving its single use is the
// lesser failure, and it still expires.
func (d *Daemon) consumeOnceGrant(vaultName string, scope vault.Scope, canon, command string, resolvedArgv []string) bool {
	if d.approvals == nil {
		return false
	}
	_, _, fingerprint := actionApprovalKey(vaultName, scope, canon, command, resolvedArgv)
	spent, err := d.approvals.ConsumeOnce(canon, fingerprint)
	return err == nil && spent
}
