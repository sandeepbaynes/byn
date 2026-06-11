package auth

// Package-level EE seam: provider interfaces live here so the enterprise
// superset binary can register additional providers without forking or editing
// this repo. See project rules: "Pluggability is mandatory." This file is
// exported in NU-4 (moved out of internal/); for now it lives here to keep
// the import graph clean while the daemon and EE seam tests use it.
//
// EE registers providers here (see project rules: pluggability is mandatory);
// exported in NU-4.

import (
	"context"
	"errors"
	"sync"
)

// VerifyRequest carries full approval context so ANY surface (TTY prompt,
// portal dialog, EE device app) can render an informed decision (spec §4.2).
// Exactly one credential field is typically set.
type VerifyRequest struct {
	Vault   string // target vault ("" ⇒ default)
	Action  string // "get", "put", "delete", "rename", "exec", "trust.grant", ...
	Command string // exec: the argv label; else ""
	BynPath string // governing .byn, when known
	Changed bool   // the .byn changed since trust (re-trust flows)

	Password      []byte // password provider input
	PresenceToken []byte // passkey provider input (one-time, vault-bound)
}

// Grant is a successful verification. Minimal today; the sessions slice
// (NU-3) will mint session state from it.
type Grant struct{ Provider string }

// Provider proves user presence for one request. Verify BLOCKS until it has
// an answer or ctx expires: implementations may take seconds to minutes (a
// device approval = initiate, then wait for the owner).
//
// Outcomes:
//   - (Grant, nil)          = approve
//   - ErrDenied             = explicit refusal — a first-class outcome, the
//     owner can say no
//   - ErrWrongCredential    = the supplied credential failed verification
//     (retryable)
//   - ctx.Err()             = timeout/cancel
//
// Implementations must be safe for concurrent use.
//
// EE registers providers here (see project rules: pluggability is mandatory);
// exported in NU-4.
type Provider interface {
	Name() string
	Verify(ctx context.Context, r VerifyRequest) (Grant, error)
}

var (
	// ErrDenied is returned when the provider explicitly refuses the request.
	// This is a first-class outcome (e.g. the owner tapped "Deny" on a device
	// approval). Distinct from ErrWrongCredential (bad creds, retryable).
	ErrDenied = errors.New("auth: denied")

	// ErrWrongCredential is returned when the supplied credential failed
	// verification (wrong password, expired token, etc.). The caller may
	// prompt for a new credential and retry.
	ErrWrongCredential = errors.New("auth: credential verification failed")
)

// Registry holds the configured providers in insertion order. The daemon owns
// one instance; the EE superset binary registers additional providers at
// startup.
//
// EE registers providers here (see project rules: pluggability is mandatory);
// exported in NU-4.
type Registry struct {
	mu     sync.RWMutex
	byName map[string]Provider
	order  []string // insertion order; last write wins on same-name Register
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{byName: make(map[string]Provider)}
}

// Register adds p to the registry. If a provider with the same name is already
// registered it is replaced (EE override pattern). Safe for concurrent use.
func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := p.Name()
	if _, exists := r.byName[name]; !exists {
		r.order = append(r.order, name)
	}
	r.byName[name] = p
}

// Lookup returns the provider registered under name, or (nil, false).
// Safe for concurrent use.
func (r *Registry) Lookup(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byName[name]
	return p, ok
}
