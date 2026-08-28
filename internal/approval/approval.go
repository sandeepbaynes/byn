// Package approval holds requests that need a human decision, so that needing
// one does not have to stop the work that raised it.
//
// A non-interactive caller — which is every agent — used to hit a password
// prompt it could not answer and die there. The queue turns that dead end into
// a reference: the caller gets an id back immediately, a person decides through
// whichever surface they have to hand, and the caller finds out on its next
// attempt. Decisions live outside the vault so the queue keeps working while
// the vault is locked.
package approval

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Filename is the queue's on-disk name inside the daemon's data dir.
const Filename = "approvals.json"

// DefaultTTL is how long a request stays answerable.
//
// It is long on purpose. Notification delivery is not something byn controls:
// a phone push can be minutes late, and hours late under a battery saver. A
// short window would expire requests through no fault of the person answering
// them, which reads as byn being broken and trains people to approve in a
// hurry.
const DefaultTTL = 6 * time.Hour

// ActionGrantFor is how long an approved unpinned command stays runnable.
//
// Approving one is not a one-off: an agent that was stopped mid-task will run
// the same command again, and a build loop may run it repeatedly, so a
// single-use grant would put the person straight back in the approval loop the
// queue exists to end. It is not permanent either — the durable answer is to
// pin the command in [exec] actions, which the refusal message says. A working
// session is the honest middle, and matches the window the queue already uses
// for how long a question stays askable.
const ActionGrantFor = 6 * time.Hour

// Rate limiting bounds how fast one project can raise requests. Any process at
// the caller's UID can invoke byn in a loop, and an approver worn down by a
// flood is the documented way these systems get beaten — an attacker does not
// need to forge a decision if they can make a person tap through one.
const (
	MaxPendingPerProject = 10
	MaxDenialsBeforeHold = 3
	DenialHoldFor        = 30 * time.Minute
)

// Status is where a request has got to. Every terminal state is distinct, so a
// caller can tell "not answered yet" from "answered no" from "nobody saw it in
// time" instead of treating any absence of approval as failure.
type Status string

const (
	// StatusPending means nobody has answered yet.
	StatusPending Status = "pending"
	// StatusApproved means a person granted it.
	StatusApproved Status = "approved"
	// StatusDenied means a person refused it.
	StatusDenied Status = "denied"
	// StatusExpired means it lapsed unanswered — distinct from denied, so a
	// caller can ask again rather than treat silence as refusal.
	StatusExpired Status = "expired"
)

// Kind classifies what is being asked for.
type Kind string

const (
	// KindTrustWidening is a .byn asking for more authority than was granted.
	KindTrustWidening Kind = "trust_widening"
	// KindActionUnpinned is a caller wanting to run a command the trusted .byn
	// does not pin.
	KindActionUnpinned Kind = "action_unpinned"
)

var (
	// ErrNotFound is returned for an unknown request id.
	ErrNotFound = errors.New("approval: request not found")
	// ErrRateLimited is returned when a project has too many requests pending.
	ErrRateLimited = errors.New("approval: too many pending requests for this project")
	// ErrOnHold is returned while a repeatedly-denied request is in cooldown.
	ErrOnHold = errors.New("approval: repeatedly denied; on hold")
)

// Requestor records who asked, so the person deciding is looking at facts byn
// can vouch for rather than a self-reported label.
//
// Every field here is read from the kernel, never from the request. That is the
// whole distinction against Reason, which the asker writes: these are the parts
// nobody can claim, so an approver can weigh the claim against them.
type Requestor struct {
	PID  int    `json:"pid"`
	Exe  string `json:"exe,omitempty"`
	Cwd  string `json:"cwd,omitempty"`
	TTY  string `json:"tty,omitempty"`
	User string `json:"user,omitempty"`
	// Agent names the process byn holds responsible: the nearest ancestor that
	// is not a shell or a wrapper. It is the same identity that decides whether
	// a caller may read back a value it created unattended, so a card and an
	// unattended value agree on who "they" are.
	//
	// It matters more than PID for deciding. `byn` itself is always the process
	// asking; the question an approver has is which agent is behind it, and a
	// pid of a shell that exited seconds ago cannot answer that.
	Agent    string `json:"agent,omitempty"`
	AgentPID int    `json:"agent_pid,omitempty"`
	// AgentKey is that identity in a form that survives a pid being reused:
	// the pid together with the process's start time. It is opaque here on
	// purpose — the queue stores it and hands it back, and only the daemon
	// knows how to decide whether a caller matches it.
	AgentKey string `json:"agent_key,omitempty"`
	// Attended records whether a person was at a terminal for this request.
	// An unattended request is the normal case for an agent, and saying so
	// stops the absence of a TTY from looking like something being hidden.
	Attended bool `json:"attended,omitempty"`
}

// String renders the requestor as one line for a person to read.
func (r Requestor) String() string {
	if r.Agent != "" && r.AgentPID != 0 {
		who := fmt.Sprintf("%s (pid %d)", r.Agent, r.AgentPID)
		if r.Attended {
			return who + ", at a terminal"
		}
		return who + ", no terminal"
	}
	if r.PID != 0 {
		return fmt.Sprintf("pid %d", r.PID)
	}
	return ""
}

// Request is one pending decision.
type Request struct {
	ID    string `json:"id"`
	Kind  Kind   `json:"kind"`
	Vault string `json:"vault,omitempty"`
	// Subject is what the decision is about — for a trust widening, the
	// canonical .byn path.
	Subject string `json:"subject"`
	// Fingerprint identifies the exact thing being asked for. Two requests with
	// the same fingerprint are the same question, and collapse into one.
	Fingerprint string `json:"fingerprint"`
	// Summary is the human-readable form: what would be granted, line by line.
	// It is what the approver actually reads, so it holds the semantic diff
	// rather than a hash — a hash is a fact nobody can make a decision from.
	Summary []string `json:"summary,omitempty"`
	// HighRisk marks the consequential kinds, so a surface can render them
	// differently instead of letting them look like routine additions.
	HighRisk  bool      `json:"high_risk,omitempty"`
	Requestor Requestor `json:"requestor"`
	// Reason is why the asker says it needs this, in its own words.
	//
	// byn cannot check it and does not try. It is shown as the claim it is,
	// because the alternative — a card reading "runs make dev" and nothing
	// else — sends the approver to ask the agent in a chat window, which is
	// exactly the interruption the queue exists to remove. An unverified
	// sentence from the asker is worth more than silence, as long as it is
	// never dressed up as something byn established.
	Reason string `json:"reason,omitempty"`
	// NeededBy is when the asker stops waiting for this. It comes from the
	// caller's own --wait-approval window, so it is a fact about the asker
	// rather than a deadline imposed on the approver.
	//
	// It exists because "asked 4h ago" and "asked 40s ago" look the same on a
	// list and are not the same question: one of them has a process sitting on
	// it right now. An approval after this time still grants — it just grants
	// to nobody who is still listening, and says so.
	NeededBy time.Time `json:"needed_by,omitempty"`
	// Anyone widens a command grant to the whole scope rather than the caller
	// that asked for it.
	//
	// A grant keyed only on the file and the command lets anything running in
	// that project use it, which is a wider authority than the question asked
	// for: the owner answered "yes, that agent may run this", and byn read it
	// as "yes, anyone here may". Binding is the default and this is the
	// deliberate exception — a shared build command, a grant meant to outlive
	// the session that asked.
	Anyone bool `json:"anyone,omitempty"`
	// Late records that the answer arrived after the asker had stopped waiting.
	// The grant is real; the process that asked for it is gone.
	Late bool `json:"late,omitempty"`

	Status     Status    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	DecidedAt  time.Time `json:"decided_at,omitempty"`
	DecidedVia string    `json:"decided_via,omitempty"`
	// Repeats counts how many times this same question has been asked while
	// pending. It is not a reason to hide the request, but it is worth showing.
	Repeats int `json:"repeats,omitempty"`
	// Denials counts consecutive denials of this fingerprint, which is what
	// puts it on hold rather than letting it be re-asked indefinitely.
	Denials int `json:"denials,omitempty"`
	// GrantedUntil is when an approved request stops authorizing anything.
	//
	// It exists for decisions that are not applied by rewriting a record. A
	// trust widening is applied by re-granting the .byn, so the grant lives in
	// the trust store and this stays zero. An unpinned command has nowhere to
	// be written down — the .byn does not list it and inventing an entry the
	// file disagrees with would be undone by the next reconcile — so the
	// approved request IS the authority, and it has to stop being one.
	GrantedUntil time.Time `json:"granted_until,omitempty"`
	// DecidedReason is why the decider decided, when they said. Carried back to
	// whoever asked, because "denied" without a reason leaves them guessing
	// between "fix it and re-ask" and "stop".
	DecidedReason string `json:"decided_reason,omitempty"`
}

// Answered reports whether a decision has been recorded.
func (r Request) Answered() bool {
	return r.Status == StatusApproved || r.Status == StatusDenied
}

// file is the on-disk shape.
type file struct {
	Requests []Request `json:"requests"`
	// Holds maps a fingerprint to the time its cooldown ends, so a question
	// that keeps being denied stops being re-askable for a while.
	Holds map[string]time.Time `json:"holds,omitempty"`
	// Denials counts consecutive denials PER QUESTION. It cannot live on the
	// request: each retry creates a fresh card, so a per-card counter would
	// reset every time and the hold would never trigger.
	Denials map[string]int `json:"denials,omitempty"`
}

// Store is the queue. Every method reloads from disk before acting, so a
// decision made through another surface is picked up without coordination.
type Store struct {
	dir string
	mu  sync.Mutex
	now func() time.Time
}

// Open returns a queue rooted at dir.
func Open(dir string) *Store { return &Store{dir: dir, now: time.Now} }

// SetClockForTesting replaces the store's clock.
func (s *Store) SetClockForTesting(now func() time.Time) { s.now = now }

func (s *Store) path() string { return filepath.Join(s.dir, Filename) }

func (s *Store) load() (*file, error) {
	b, err := os.ReadFile(s.path()) // #nosec G304 -- daemon-owned data dir
	if errors.Is(err, os.ErrNotExist) {
		return &file{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("approval: parse queue: %w", err)
	}
	return &f, nil
}

func (s *Store) save(f *file) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path() + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path())
}

// expire marks anything past its deadline, in place.
func (s *Store) expire(f *file, now time.Time) {
	for i := range f.Requests {
		if f.Requests[i].Status == StatusPending && now.After(f.Requests[i].ExpiresAt) {
			f.Requests[i].Status = StatusExpired
		}
	}
}

// Enqueue records a request and returns it.
//
// Asking the same question twice does not produce a second card: an identical
// fingerprint that is still pending is returned as-is with its repeat count
// bumped. An agent that retries in a loop therefore cannot flood the approver,
// and the person sees one decision to make rather than a hundred.
func (s *Store) Enqueue(req Request) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := s.load()
	if err != nil {
		return Request{}, err
	}
	now := s.now()
	s.expire(f, now)

	if until, held := f.Holds[req.Fingerprint]; held {
		if now.Before(until) {
			return Request{}, fmt.Errorf("%w until %s", ErrOnHold, until.Format(time.RFC3339))
		}
		delete(f.Holds, req.Fingerprint)
		delete(f.Denials, req.Fingerprint) // cooldown served; start counting again
	}

	pending := 0
	for i := range f.Requests {
		r := &f.Requests[i]
		if r.Status != StatusPending {
			continue
		}
		if r.Fingerprint == req.Fingerprint && r.Subject == req.Subject {
			r.Repeats++
			// A retry that explains itself improves a card that did not. The
			// first reason otherwise stands: it is the one that raised the
			// question, and letting each retry overwrite it would let a
			// request's stated purpose drift while the approver is reading it.
			if r.Reason == "" && req.Reason != "" {
				r.Reason = req.Reason
			}
			out := *r
			if err := s.save(f); err != nil {
				return Request{}, err
			}
			return out, nil
		}
		if r.Subject == req.Subject {
			pending++
		}
	}
	if pending >= MaxPendingPerProject {
		return Request{}, ErrRateLimited
	}

	req.ID = newID()
	req.Status = StatusPending
	req.CreatedAt = now
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = now.Add(DefaultTTL)
	}
	f.Requests = append(f.Requests, req)
	if err := s.save(f); err != nil {
		return Request{}, err
	}
	return req, nil
}

// Decide records an answer.
//
// Deciding is idempotent: answering an already-answered request returns the
// decision already on file instead of failing. A decision can arrive twice —
// two surfaces racing, or a late notification — and neither should turn into an
// error the caller has to interpret.
func (s *Store) Decide(id string, approve bool, via, reason string) (Request, error) {
	return s.DecideFor(id, approve, via, reason, 0)
}

// DecideFor answers a request and, for a command grant, sets how long it runs
// free. A zero window means the default.
//
// The owner setting the window is the other half of the asker stating a
// deadline: a command wanted once for the next ten minutes and a command wanted
// all afternoon are different grants, and giving both of them six hours makes
// the shorter one an unnecessary standing authority.
func (s *Store) DecideFor(id string, approve bool, via, reason string, grantFor time.Duration) (Request, error) {
	return s.decide(id, approve, via, reason, grantFor, false)
}

// DecideForAnyone is DecideFor with the grant widened past the caller that
// asked, which is a deliberate act and is recorded as one.
func (s *Store) DecideForAnyone(id string, approve bool, via, reason string, grantFor time.Duration) (Request, error) {
	return s.decide(id, approve, via, reason, grantFor, true)
}

func (s *Store) decide(id string, approve bool, via, reason string,
	grantFor time.Duration, anyone bool) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := s.load()
	if err != nil {
		return Request{}, err
	}
	now := s.now()
	s.expire(f, now)

	for i := range f.Requests {
		r := &f.Requests[i]
		if r.ID != id {
			continue
		}
		if r.Answered() {
			return *r, nil // already decided; report what was decided
		}
		if r.Status == StatusExpired {
			return *r, nil
		}
		if approve {
			r.Status = StatusApproved
			if r.Kind == KindActionUnpinned {
				window := grantFor
				if window <= 0 {
					window = ActionGrantFor
				}
				r.GrantedUntil = now.Add(window)
			}
			// An answer that arrives after the asker gave up is still an
			// answer, and it still grants. What it does not do is reach the
			// process that asked — so it is recorded, and every surface can say
			// so rather than leaving a grant nobody can account for.
			if !r.NeededBy.IsZero() && now.After(r.NeededBy) {
				r.Late = true
			}
			if anyone {
				r.Anyone = true
			}
			r.Denials = 0
			delete(f.Denials, r.Fingerprint)
			delete(f.Holds, r.Fingerprint)
		} else {
			r.Status = StatusDenied
			if f.Denials == nil {
				f.Denials = map[string]int{}
			}
			f.Denials[r.Fingerprint]++
			r.Denials = f.Denials[r.Fingerprint]
			// A question that keeps being answered "no" stops being askable for
			// a while. Without this, refusing costs the approver something and
			// costs the asker nothing.
			if r.Denials >= MaxDenialsBeforeHold {
				if f.Holds == nil {
					f.Holds = map[string]time.Time{}
				}
				f.Holds[r.Fingerprint] = now.Add(DenialHoldFor)
			}
		}
		r.DecidedAt = now
		r.DecidedVia = via
		r.DecidedReason = reason
		out := *r
		if err := s.save(f); err != nil {
			return Request{}, err
		}
		return out, nil
	}
	return Request{}, ErrNotFound
}

// LastDenial returns the most recent refusal of this exact question, if there
// is one that has not been superseded by an approval.
//
// It exists so a refused command hits a wall rather than silently raising a
// fresh request. Re-asking a person who just said no is how approval fatigue
// starts, and the asker learns nothing from doing it.
func (s *Store) LastDenial(subject, fingerprint string) (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return Request{}, false
	}
	// The LAST word wins, so find the most recent decision of any kind first and
	// only then ask what it was.
	//
	// Deciding inside the loop does not work: the requests are in no particular
	// order, so an older approval seen before a newer refusal ended the search
	// and reported "not refused". That is the wrong way round — it turned the
	// wall off for exactly the command a person had most recently said no to.
	var latest Request
	var found bool
	for _, r := range f.Requests {
		if r.Subject != subject || r.Fingerprint != fingerprint {
			continue
		}
		if !r.Answered() {
			continue // still pending: not a word either way yet
		}
		if !found || r.DecidedAt.After(latest.DecidedAt) {
			latest, found = r, true
		}
	}
	if !found || latest.Status != StatusDenied {
		return Request{}, false
	}
	return latest, true
}

// ActionGranted reports whether an approved, still-valid decision authorizes
// this exact command on this exact .byn.
//
// Matching is on the fingerprint, which is what made the two questions "the
// same question" when the request was raised — so the thing that collapses
// duplicate cards is the same thing that recognises the answer, and they cannot
// drift apart.
func (s *Store) ActionGranted(subject, fingerprint string) (bool, error) {
	ok, _, err := s.ActionGrantedUntil(subject, fingerprint)
	return ok, err
}

// ActionGrantedUntil is ActionGranted, and also says when the grant lapses.
func (s *Store) ActionGrantedUntil(subject, fingerprint string) (bool, time.Time, error) {
	return s.ActionGrantFor(subject, fingerprint, nil)
}

// ActionGrantFor is ActionGrantedUntil restricted to grants the caller may use.
//
// usable decides whether a particular grant belongs to whoever is asking now;
// nil accepts any. The queue does not know what identity means — it holds the
// recorded one and asks the daemon, which is the only part that can compare a
// live process against it.
func (s *Store) ActionGrantFor(subject, fingerprint string, usable func(Request) bool) (bool, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return false, time.Time{}, err
	}
	now := s.now()
	for _, r := range f.Requests {
		if r.Kind != KindActionUnpinned || r.Status != StatusApproved {
			continue
		}
		if r.Subject != subject || r.Fingerprint != fingerprint {
			continue
		}
		if !now.Before(r.GrantedUntil) {
			continue
		}
		// Keep looking rather than stopping at the first unusable grant: the
		// same command may have been approved twice, once bound to a session
		// that has since gone and once for anyone.
		if usable != nil && !usable(r) {
			continue
		}
		return true, r.GrantedUntil, nil
	}
	return false, time.Time{}, nil
}

// Get returns one request by id.
func (s *Store) Get(id string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return Request{}, err
	}
	s.expire(f, s.now())
	for _, r := range f.Requests {
		if r.ID == id {
			return r, nil
		}
	}
	return Request{}, ErrNotFound
}

// List returns requests, newest first. Passing an empty status returns
// everything still on file.
func (s *Store) List(status Status) ([]Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	now := s.now()
	s.expire(f, now)
	if err := s.save(f); err != nil {
		return nil, err
	}
	out := make([]Request, 0, len(f.Requests))
	for _, r := range f.Requests {
		if status == "" || r.Status == status {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// Prune drops answered and expired requests older than keepFor, so the queue
// does not grow without bound. Pending requests are never dropped: an
// unanswered question disappearing on its own is exactly the failure this queue
// exists to prevent.
func (s *Store) Prune(keepFor time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return 0, err
	}
	now := s.now()
	s.expire(f, now)
	cutoff := now.Add(-keepFor)
	kept := f.Requests[:0]
	dropped := 0
	for _, r := range f.Requests {
		if r.Status != StatusPending && r.CreatedAt.Before(cutoff) {
			dropped++
			continue
		}
		kept = append(kept, r)
	}
	f.Requests = kept
	for fp, until := range f.Holds {
		if now.After(until) {
			delete(f.Holds, fp)
		}
	}
	if err := s.save(f); err != nil {
		return 0, err
	}
	return dropped, nil
}

// newID returns a short random identifier. It is meant to be quoted back by a
// person into another terminal, so it is hex and short rather than a UUID.
func newID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A collision here costs a duplicate card, not a security property.
		return hex.EncodeToString([]byte(time.Now().Format("150405.000000")))
	}
	return hex.EncodeToString(b[:])
}
