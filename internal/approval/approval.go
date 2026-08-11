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
type Requestor struct {
	PID  int    `json:"pid"`
	Exe  string `json:"exe,omitempty"`
	Cwd  string `json:"cwd,omitempty"`
	TTY  string `json:"tty,omitempty"`
	User string `json:"user,omitempty"`
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
func (s *Store) Decide(id string, approve bool, via string) (Request, error) {
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
		out := *r
		if err := s.save(f); err != nil {
			return Request{}, err
		}
		return out, nil
	}
	return Request{}, ErrNotFound
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
