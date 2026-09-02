package daemon

import (
	"context"
	"sync"
	"time"

	"github.com/sandeepbaynes/byn/internal/approval"
	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// defaultWatchTimeout bounds a wait the caller did not bound. Long enough that
// an agent can hand a request to a person who is away from their desk, short
// enough that a forgotten watcher is not a connection held for a day.
const defaultWatchTimeout = 30 * time.Minute

// maxWatchTimeout is the ceiling. A watch holds a connection and a goroutine for
// its whole life, so an arbitrary number arriving over IPC is a resource
// question, not a preference.
const maxWatchTimeout = 6 * time.Hour

// watchPollInterval is the backstop for the notify path.
//
// Decisions are broadcast in-process, so the normal case wakes immediately and
// never waits for this. It exists for the outcome nothing announces: expiry,
// which is applied lazily when the store is next read, so there is no moment
// anybody could publish. Rather than model expiry as an event, the waiter looks
// again on a slow tick and finds it.
const watchPollInterval = 2 * time.Second

// decisionBroadcaster wakes waiters the instant a request is answered.
//
// The alternative is polling, which is what callers do today: `byn exec
// --wait-approval` re-runs the entire exec call every two seconds to discover an
// answer that the daemon knew about immediately. That is wasted work on both
// sides and, worse, it can only observe success — a poller that re-runs exec
// cannot tell "denied" from "not yet", which is the difference between an agent
// that stops and one that keeps asking.
//
// Every decision passes through this process, so an in-process broadcast is
// sufficient and needs no persistence: a waiter that misses a notification still
// finds the answer on its next tick, and a waiter that starts after the decision
// reads it before ever waiting.
type decisionBroadcaster struct {
	mu      sync.Mutex
	waiters map[string][]chan struct{}
}

func newDecisionBroadcaster() *decisionBroadcaster {
	return &decisionBroadcaster{waiters: make(map[string][]chan struct{})}
}

// subscribe returns a channel closed when id is decided, and the unsubscribe to
// call when the caller stops waiting. Buffered-by-close rather than by value, so
// a notification cannot be lost between the broadcast and the receive.
func (b *decisionBroadcaster) subscribe(id string) (<-chan struct{}, func()) {
	ch := make(chan struct{})
	b.mu.Lock()
	b.waiters[id] = append(b.waiters[id], ch)
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		rest := b.waiters[id][:0]
		for _, c := range b.waiters[id] {
			if c != ch {
				rest = append(rest, c)
			}
		}
		if len(rest) == 0 {
			delete(b.waiters, id)
			return
		}
		b.waiters[id] = rest
	}
}

// publish wakes everyone waiting on id. Safe to call for an id nobody watches,
// which is the common case — most requests are answered with no agent waiting.
func (b *decisionBroadcaster) publish(id string) {
	b.mu.Lock()
	chans := b.waiters[id]
	delete(b.waiters, id)
	b.mu.Unlock()
	for _, c := range chans {
		close(c)
	}
}

// watchResponse renders a request as the answer an asker branches on.
func watchResponse(r approval.Request, timedOut bool) ipc.ApprovalWatchResp {
	resp := ipc.ApprovalWatchResp{
		ApprovalID: r.ID,
		Status:     string(r.Status),
		Reason:     r.DecidedReason,
		DecidedVia: r.DecidedVia,
		Once:       r.Once,
		TimedOut:   timedOut,
	}
	if !r.GrantedUntil.IsZero() {
		resp.GrantedUntil = r.GrantedUntil.Unix()
	}
	return resp
}

// clampWatchTimeout keeps a caller-supplied wait inside what the daemon will
// hold a connection open for.
func clampWatchTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return defaultWatchTimeout
	}
	d := time.Duration(seconds) * time.Second
	if d > maxWatchTimeout {
		return maxWatchTimeout
	}
	return d
}

// handleApprovalWatch blocks until the request a ticket speaks for is answered.
//
// Authorization is possession of the ticket, and nothing else. The daemon does
// not check who is calling: the point of the ticket is that holding it IS the
// proof, which is what lets a privsep child — running as a different user, with
// no session and no password — learn the outcome of its own request without
// being given any wider access to the queue.
//
// An unknown ticket is refused without saying whether it was wrong or merely
// expired. The distinction is worth nothing to a legitimate holder, who knows
// which ticket it has, and is a probe oracle for anybody else.
func (d *Daemon) handleApprovalWatch(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ApprovalWatchReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	pending, ok := d.approvals.ByWatchTicket(req.Ticket)
	if !ok {
		return ipc.NewError(env.ID, ipc.CodeNotFound,
			"no request matches that watch ticket",
			"a ticket is issued once, to whoever raised the request; it cannot be re-requested")
	}
	// Already answered: return it now rather than waiting for an event that has
	// been and gone. This is also the path a slow agent takes, and it must work
	// exactly as well as the fast one.
	if pending.Answered() || pending.Status == approval.StatusExpired {
		return newResp(env.ID, watchResponse(pending, false))
	}

	ch, unsubscribe := d.decisions.subscribe(pending.ID)
	defer unsubscribe()

	// Re-read after subscribing. Without this a decision landing between the
	// lookup above and the subscription is missed entirely, and the caller waits
	// out its whole timeout for something that already happened.
	if again, ok := d.approvals.ByWatchTicket(req.Ticket); ok &&
		(again.Answered() || again.Status == approval.StatusExpired) {
		return newResp(env.ID, watchResponse(again, false))
	}

	deadline := time.After(clampWatchTimeout(req.TimeoutSeconds))
	tick := time.NewTicker(watchPollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			// The caller went away. Nothing to report to nobody.
			return newResp(env.ID, watchResponse(pending, true))
		case <-ch:
			latest, _ := d.approvals.ByWatchTicket(req.Ticket)
			return newResp(env.ID, watchResponse(latest, false))
		case <-tick.C:
			// Catches expiry, which nothing publishes: it is applied lazily when
			// the store is read, so reading is the only way to observe it.
			latest, found := d.approvals.ByWatchTicket(req.Ticket)
			if found && (latest.Answered() || latest.Status == approval.StatusExpired) {
				return newResp(env.ID, watchResponse(latest, false))
			}
		case <-deadline:
			// Still pending, and the caller stopped waiting. Reported as a
			// timeout rather than a decision, because "nobody answered yet" and
			// "the answer was no" must never be confusable by an agent.
			latest, found := d.approvals.ByWatchTicket(req.Ticket)
			if !found {
				latest = pending
			}
			return newResp(env.ID, watchResponse(latest, true))
		}
	}
}

// handleApprovalCancel withdraws a request the asker no longer needs.
//
// Ticket-authorized like watch, and for a sharper reason: cancelling by request
// id would let any local process take another agent's question off the owner's
// list, which is a denial of service against work the owner was about to allow.
func (d *Daemon) handleApprovalCancel(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ApprovalCancelReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	pending, ok := d.approvals.ByWatchTicket(req.Ticket)
	if !ok {
		return ipc.NewError(env.ID, ipc.CodeNotFound,
			"no request matches that watch ticket",
			"a ticket is issued once, to whoever raised the request; it cannot be re-requested")
	}
	out, err := d.approvals.Cancel(pending.ID)
	if err != nil {
		return internalErr(env.ID, err)
	}
	// Withdrawing is a security event too: something asked for authority and
	// then took the question back, and an owner reading the log later should not
	// find a raise with no ending.
	d.auditEmit(ctx, defaultIfEmpty(out.Vault, vault.DefaultVaultName), audit.Event{
		Op:      string(ipc.OpApprovalCancel),
		Outcome: audit.OutcomeOK,
		BynPath: out.Subject,
		Command: "approval " + out.ID + " withdrawn by the asker",
	})
	// Wake any watcher: a cancel is an outcome, and an agent waiting on its own
	// request should not sit out its timeout because the end came from itself.
	d.decisions.publish(out.ID)
	return newResp(env.ID, ipc.ApprovalCancelResp{ApprovalID: out.ID, Status: string(out.Status)})
}

// newResp is the response-or-internal-error idiom used across the daemon,
// factored out here because a watch has four exit paths and repeating the
// two-line marshal check at each one buries what they actually differ in.
func newResp(id string, payload any) *ipc.Envelope {
	out, err := ipc.NewResponse(id, payload)
	if err != nil {
		return internalErr(id, err)
	}
	return out
}
