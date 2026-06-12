package daemon

// providers.go — daemon-side auth.Provider implementations.
//
// Two built-in providers are registered in New():
//   - "password" — verifies the master password via st.VerifyPassword (rate-limited + audit).
//   - "passkey"  — consumes a one-time presence token (vault-bound, minted on
//     successful passkey ceremony).
//
// EE registers providers here (see project rules: pluggability is mandatory);
// exported in NU-4.

import (
	"context"
	"fmt"
	"time"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// ---- passwordProvider ------------------------------------------------------

// passwordProvider is the built-in master-password verifier. It:
//  1. Runs the shared rate-limit check.
//  2. Calls st.VerifyPassword(r.Password).
//  3. On failure: records the limiter failure + emits a wrong-password audit
//     event, returns auth.ErrWrongCredential.
//  4. On success: records the limiter success.
//
// This is the EXACT body of the former authorizeWithPassword, extracted so
// dispatch.go can delegate to it via the registry.
type passwordProvider struct{ d *Daemon }

func (p *passwordProvider) Name() string { return "password" }

func (p *passwordProvider) Verify(ctx context.Context, r auth.VerifyRequest) (auth.Grant, error) {
	vaultName := defaultIfEmpty(r.Vault, vault.DefaultVaultName)

	// Resolve the vault store. openVault can return vault.ErrNotInit,
	// vault.ErrFingerprintMismatch, or other errors. These are NOT
	// wrong-password — wrapping them lets mapProviderErr surface the correct
	// code (CodeNotInit, CodeFingerprint, etc.) instead of CodeWrongPassword.
	entry, err := p.d.openVault(ctx, vaultName)
	if err != nil {
		return auth.Grant{}, fmt.Errorf("auth: open vault: %w", err)
	}
	st := entry.store

	// Rate-limit check. *auth.RetryAfterError is returned directly —
	// mapProviderErr uses errors.As to extract it; no wrapper needed.
	if err := p.d.limiter.Check(); err != nil {
		return auth.Grant{}, err
	}

	if err := st.VerifyPassword(r.Password); err != nil {
		_ = p.d.limiter.RecordFailure()
		p.d.auditEmit(ctx, vaultName, audit.Event{
			Op:        "vault.authorize",
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(ipc.CodeWrongPassword),
		})
		return auth.Grant{}, auth.ErrWrongCredential
	}
	_ = p.d.limiter.RecordSuccess()
	return auth.Grant{Provider: p.Name()}, nil
}

// ---- passkeyProvider -------------------------------------------------------

// passkeyProvider is the built-in presence-token verifier. A presence token
// is a one-time, vault-bound proof that a fresh passkey ceremony just
// succeeded. It is consumed (burned) on the first Verify call, regardless of
// whether the vault-name check passes — fail-closed by design.
type passkeyProvider struct{ d *Daemon }

func (p *passkeyProvider) Name() string { return "passkey" }

func (p *passkeyProvider) Verify(_ context.Context, r auth.VerifyRequest) (auth.Grant, error) {
	vaultName := defaultIfEmpty(r.Vault, vault.DefaultVaultName)
	if p.d.presenceTokens.consume(r.PresenceToken, vaultName, time.Now()) {
		return auth.Grant{Provider: p.Name()}, nil
	}
	return auth.Grant{}, auth.ErrDenied
}
