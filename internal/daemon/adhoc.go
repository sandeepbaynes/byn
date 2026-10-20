package daemon

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sandeepbaynes/byn/internal/approval"
	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// Ad hoc requests: "may I run THIS command, HERE, with THESE named variables
// from THIS scope" — asked by anything on the machine, with no .byn involved.
//
// The .byn model anchors authority to a file an owner trusted. An ad hoc
// request has no file, so everything the file would have said is on the
// request instead, and everything on the request is on the card: the exact
// command, the directory, the names, the vault and scope, and who asked. The
// fingerprint binds all of it — change any one and it is a different question
// — and the grant is a capability sealed for exactly those names at approval
// time, from the approver's password. A yes hands over what the card said and
// nothing else, and the run works while the vault is locked the same way a
// trusted .byn does.
//
// A trusted .byn in the same directory is bypassed, not consulted: the request
// is for what the file does not cover, the file is never changed by approving,
// and the card says that a file is there. The owner chose this over refusing,
// because the case ad hoc exists for is the one-off that should not go into
// the file.

// maxAdhocVars bounds a request. A card with more names than this is not one
// a person reads; a caller wanting that much should be trusted through a .byn.
const maxAdhocVars = 64

// adhocVars validates and normalizes the names an ad hoc request asks for:
// exact names only, de-duplicated, sorted so the fingerprint does not depend
// on the order they were typed.
func adhocVars(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, errors.New("an ad hoc request names at least one variable: byn exec --var NAME")
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, n := range in {
		n = strings.TrimSpace(n)
		// No wildcard, by design: the card lists what a yes hands over, and
		// "everything" is not a list. The other characters have no place in
		// an environment variable name and would only ever be a trick.
		if n == "" || strings.ContainsAny(n, "*?[]= \t\r\n\x00") {
			return nil, fmt.Errorf("--var takes an exact variable name, not %q", n)
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	if len(out) > maxAdhocVars {
		return nil, fmt.Errorf("an ad hoc request may name at most %d variables; a project wanting more belongs in a .byn", maxAdhocVars)
	}
	sort.Strings(out)
	return out, nil
}

// adhocSubject is the directory the command runs in, which is what an ad hoc
// request is anchored to. The kernel's answer is preferred because it cannot be
// claimed; the CLI's is used only where byn cannot ask (macOS), and the card
// shows it as where the request was made rather than treating it as proof.
func (d *Daemon) adhocSubject(ctx context.Context, req ipc.ExecFetchReq) string {
	if cwd := procCwd(callerFrom(ctx).PID); cwd != "" {
		return trust.Canonicalize(cwd)
	}
	if req.Cwd != "" {
		return trust.Canonicalize(req.Cwd)
	}
	return ""
}

// adhocApprovalKey derives what identifies one ad hoc question: the command a
// person reads, the summary line, and the fingerprint. The fingerprint carries
// the vault, the scope, the directory, the exact argv and the names, so an
// approval is an answer to exactly one of those combinations.
//
// argv is joined on a separator no argument contains rather than on a space,
// so "a b" as one argument and as two are different commands here too.
func adhocApprovalKey(vaultName string, scope vault.Scope, subject string, argv, vars []string) (cmd string, summary []string, fingerprint string) {
	cmd = strings.Join(argv, " ")
	if len(cmd) > 200 { // the card is read by a person; keep it legible
		cmd = cmd[:200] + "…"
	}
	summary = []string{"runs " + cmd}
	fingerprint = trust.Policy{
		Vault:     defaultIfEmpty(vaultName, vault.DefaultVaultName),
		Project:   subject,
		Env:       scopeLabel(scope),
		EnvGrants: vars,
		Actions:   []string{strings.Join(argv, "\x1f")},
	}.Hash()
	return cmd, summary, fingerprint
}

// recordScopeClash reports why a trusted .byn is not the contract for this
// request, or "" when it is.
//
// A record is the authority for one vault, and the file is the authority for
// the project and env it pins. Exec was looking the record up by path alone,
// so a file trusted into one vault was honoured as the contract for any vault,
// and --project or --env on the command line quietly replaced what the file
// said. Approval cards then described the file's scope while the run used
// another.
//
// The vault is checked against the RECORD: a record's keys and MAC belong to
// one vault, and moving a file to another vault means trusting it there.
// Project and env are checked against the FILE as it is now: a flag that
// contradicts the file is a clash, while a file whose own scope line changed
// since it was trusted is a scope move — a widening, raised for approval by
// the reconcile step that follows, not a flag to refuse. A field the file
// leaves unset stays selectable by flag: a .byn that names no env is meant for
// every env of its project.
func recordScopeClash(rec trust.Record, pinned ipc.Scope, vaultName string, scope vault.Scope) string {
	if recVault := defaultIfEmpty(rec.Vault, vault.DefaultVaultName); recVault != vaultName {
		return fmt.Sprintf("is trusted for vault %s, not %s", recVault, vaultName)
	}
	if pinned.Project != "" && pinned.Project != scope.Project {
		return fmt.Sprintf("pins project %s, not %s", pinned.Project, scope.Project)
	}
	if pinned.Env != "" && pinned.Env != scope.Env {
		return fmt.Sprintf("pins env %s, not %s", pinned.Env, scope.Env)
	}
	return ""
}

// scopeClashHint tells a caller whose flags contradict the .byn what it can do
// instead. There are two honest ways out, and the message names both rather
// than silently picking one: name the variables and ask ad hoc, which is what
// a caller that meant to reach another scope was asking for; or set the file
// aside with --no-discovery and run on the whole scope with the vault's
// password, exactly as from a directory with no .byn. "Trust the file for that
// scope" is not a way out and is no longer offered: trust is granted on the
// file's own scope line, which is the thing being contradicted.
func scopeClashHint(vaultName string, scope vault.Scope) string {
	where := fmt.Sprintf("--vault %s --project %s --env %s", vaultName, scope.Project, scope.Env)
	return fmt.Sprintf("name what you need and have it approved: byn exec %s --var NAME -- COMMAND;"+
		" or set the .byn aside and run on the whole scope with the vault password: byn exec --no-discovery %s -- COMMAND",
		where, where)
}

// authorizeAdhoc is the gate for a request that names its variables. It
// returns the names (sorted), the argv to run, and the values when a standing
// grant or supplied credentials authorize the run now; otherwise it raises the
// question and returns the approval_pending error the caller sees.
func (d *Daemon) authorizeAdhoc(ctx context.Context, id string, req ipc.ExecFetchReq, st *vault.Store,
	scope vault.Scope, vaultName, canon string) (vars, argv []string, values []ipc.ExecFetchValue, le *ipc.Envelope) {

	vars, verr := adhocVars(req.Vars)
	if verr != nil {
		return nil, nil, nil, badRequest(id, verr)
	}
	if req.Alias != "" {
		return nil, nil, nil, ipc.NewError(id, ipc.CodeBadRequest,
			"an ad hoc request runs a command, not an alias — aliases come from a .byn",
			"byn exec --var NAME -- COMMAND")
	}
	if len(req.Argv) == 0 {
		return nil, nil, nil, ipc.NewError(id, ipc.CodeBadRequest,
			"an ad hoc request names a command", "byn exec --var NAME -- COMMAND")
	}
	if d.approvals == nil {
		return nil, nil, nil, internalErr(id, errors.New("no approval queue"))
	}
	subject := d.adhocSubject(ctx, req)
	if subject == "" {
		return nil, nil, nil, ipc.NewError(id, ipc.CodeBadRequest,
			"cannot tell which directory this would run in", "run it from the project directory")
	}
	cmd, summary, fingerprint := adhocApprovalKey(vaultName, scope, subject, req.Argv, vars)
	gets := strings.Join(vars, ", ")

	// A standing grant for exactly this question, usable by this caller.
	if grant, ok, gerr := d.approvals.ActionGrantRequest(subject, fingerprint, d.grantUsableBy(ctx)); gerr == nil && ok {
		values, le = d.adhocValues(ctx, id, st, scope, vars, grant.Capability)
		if le != nil {
			return nil, nil, nil, le
		}
		spent, _ := d.approvals.ConsumeOnce(subject, fingerprint)
		ev := audit.Event{
			Op: "exec.adhoc_approved", Outcome: audit.OutcomeOK,
			Project: scope.Project, Env: scope.Env, BynPath: subject,
			Command: cmd + " (gets " + gets + ")",
		}
		if spent {
			ev.Command += " (single-use grant spent)"
		}
		d.auditEmit(ctx, vaultName, ev)
		return vars, req.Argv, values, nil
	}

	// Credentials in hand — an owner at a terminal. Authorize on the spot, as
	// ad hoc exec always has, but hand over the named variables only.
	if len(req.Password) > 0 || len(req.PresenceToken) > 0 {
		if le := d.authorizeActionAlways(ctx, id, vaultName, st,
			"ad hoc exec requires authorization", "supply the master password",
			req.Password, req.PresenceToken); le != nil {
			return nil, nil, nil, le
		}
		values, le = d.adhocValuesNow(ctx, id, st, scope, vars, req.Password)
		if le != nil {
			return nil, nil, nil, le
		}
		return vars, req.Argv, values, nil
	}

	// Already refused? A wall, not a fresh card — the same rule as a .byn
	// command, for the same reason.
	if denial, refused := d.approvals.LastDenial(subject, fingerprint); refused && !req.ForceAsk {
		msg := fmt.Sprintf("%s was refused at %s", cmd, denial.DecidedAt.Format(time.RFC3339))
		if denial.DecidedReason != "" {
			msg += ": " + denial.DecidedReason
		}
		return nil, nil, nil, ipc.NewErrorWithDetails(id, ipc.CodeTrustDenied, msg,
			"change what you are asking for, or ask again with: byn exec --force-ask",
			map[string]string{
				"denied_at": strconv.FormatInt(denial.DecidedAt.Unix(), 10),
				"reason":    denial.DecidedReason,
				"cwd":       subject,
				"command":   cmd,
			})
	}

	ticket, watchHash, terr := approval.NewWatchTicket()
	if terr != nil {
		return nil, nil, nil, internalErr(id, terr)
	}
	requestor := d.requestorOf(ctx, vaultName, req)
	if requestor.Cwd == "" {
		requestor.Cwd = subject
	}
	pending, created, err := d.approvals.Enqueue(approval.Request{
		WatchHash:   watchHash,
		Kind:        approval.KindAdhoc,
		Vault:       vaultName,
		Project:     scope.Project,
		Env:         scope.Env,
		Subject:     subject,
		Fingerprint: fingerprint,
		Summary:     summary,
		Gets:        vars,
		Beside:      canon,
		// Flagged when a trusted file is being stepped around: the owner
		// asked for that to be visible, not forbidden.
		HighRisk:  canon != "",
		Requestor: requestor,
		Reason:    requestReason(req.Reason),
		NeededBy:  neededBy(req.WaitSeconds),
		AskOnce:   req.AskOnce,
	})
	switch {
	case errors.Is(err, approval.ErrOnHold):
		return nil, nil, nil, ipc.NewError(id, ipc.CodeTrustDenied,
			fmt.Sprintf("%s was already refused here and is on hold", cmd),
			"change what you are asking for, or wait for the hold to lapse")
	case errors.Is(err, approval.ErrRateLimited):
		return nil, nil, nil, ipc.NewError(id, ipc.CodeTrustDenied,
			fmt.Sprintf("%s has too many approvals already waiting", subject),
			"answer the pending requests first: byn approve")
	case err != nil:
		return nil, nil, nil, internalErr(id, fmt.Errorf("queue approval: %w", err))
	}

	d.auditEmit(ctx, vaultName, audit.Event{
		Op: "approval.raise", Outcome: audit.OutcomePending,
		Project: scope.Project, Env: scope.Env, BynPath: subject,
		Command: "ad hoc approval raised " + pending.ID + ": " + strings.Join(summary, "; ") +
			" (gets " + gets + ")" + auditReason(pending),
	})
	return nil, nil, nil, ipc.NewErrorWithDetails(id, ipc.CodeApprovalPending,
		fmt.Sprintf("%s is not covered by a trusted .byn here — approval %s is waiting (gets %s from %s/%s)",
			cmd, pending.ID, gets, vaultName, scopeLabel(scope)),
		"approve it with: "+approveHint(vaultName, pending.ID)+reasonHint(pending),
		approvalDetails(pending, cmd, ticketIfCreated(ticket, created)))
}

// adhocValues opens the values an approved ad hoc grant covers. The sealed
// capability is the normal path and needs no vault key. A grant without one —
// sealed on a machine with no fingerprint — falls back to the in-memory key
// while the vault is open, and otherwise says so rather than starting the
// command without the values it was approved to get.
func (d *Daemon) adhocValues(ctx context.Context, id string, st *vault.Store, scope vault.Scope,
	vars []string, blob []byte) ([]ipc.ExecFetchValue, *ipc.Envelope) {

	if len(blob) > 0 {
		return d.openCapabilityValues(ctx, id, st, scope, blob, nameSet(vars), false, "")
	}
	if !st.IsLocked() {
		return d.execValuesFromVaultKey(ctx, id, st, scope, vars, false)
	}
	return nil, ipc.NewError(id, ipc.CodeLocked,
		"this grant carries no sealed keys and the vault is locked",
		"byn unlock, then run it again")
}

// adhocValuesNow opens the named values for a caller that authorized with
// credentials on the spot: the in-memory key when the vault is open, else a
// capability sealed from the password for this one run and discarded.
func (d *Daemon) adhocValuesNow(ctx context.Context, id string, st *vault.Store, scope vault.Scope,
	vars []string, password []byte) ([]ipc.ExecFetchValue, *ipc.Envelope) {

	if !st.IsLocked() {
		return d.execValuesFromVaultKey(ctx, id, st, scope, vars, false)
	}
	if len(password) == 0 {
		return nil, ipc.NewError(id, ipc.CodeLocked, "vault is locked",
			"byn unlock, or supply the master password")
	}
	blob, err := d.sealExecCapabilityWithKey(ctx, st, scope, vars, false, password, nil)
	if err != nil {
		return nil, mapVaultErr(id, err)
	}
	if len(blob) == 0 {
		return nil, nil // none of the names has a value yet; reported as missing
	}
	return d.openCapabilityValues(ctx, id, st, scope, blob, nameSet(vars), false, "")
}

// scopeOf is the request's scope with defaults filled in, which after the
// clash check is also the scope a trusted .byn's run uses.
func scopeOf(s ipc.Scope) vault.Scope {
	return vault.Scope{
		Project: defaultIfEmpty(s.Project, vault.DefaultProjectName),
		Env:     defaultIfEmpty(s.Env, vault.DefaultEnvName),
	}
}

// execGets is what a .byn run hands the command, for the card: the names, or
// everything in the scope.
type execGets struct {
	Names []string
	All   bool
}

func nameSet(names []string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out
}

// approveHint is the command that answers a request, including the vault when
// it is not the default: `byn approve` lists the vault in scope where it is
// run, which from another project is not this one.
func approveHint(vaultName, id string) string {
	if vaultName == "" || vaultName == vault.DefaultVaultName {
		return "byn approve " + id
	}
	return "byn approve --vault " + vaultName + " " + id
}
