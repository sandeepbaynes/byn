package passkey

import (
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// ToCredential maps a stored vault.Passkey into the go-webauthn credential type
// used in ceremonies (assertion verifies a signature against the stored public
// key and checks the sign counter for clone detection).
func ToCredential(pk vault.Passkey) webauthn.Credential {
	return webauthn.Credential{
		ID:        pk.CredentialID,
		PublicKey: pk.PublicKey,
		Transport: parseTransports(pk.Transports),
		// BackupEligible must match what the authenticator asserts at login, or
		// ValidateLogin rejects it ("Backup Eligible flag inconsistency").
		Flags: webauthn.CredentialFlags{
			BackupEligible: pk.BackupEligible,
			BackupState:    pk.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    pk.AAGUID,
			SignCount: pk.SignCount,
		},
	}
}

// FromCredential maps a verified go-webauthn credential (e.g. the result of a
// successful registration ceremony) into a vault.Passkey for storage.
func FromCredential(c webauthn.Credential) vault.Passkey {
	return vault.Passkey{
		CredentialID:   c.ID,
		PublicKey:      c.PublicKey,
		SignCount:      c.Authenticator.SignCount,
		AAGUID:         c.Authenticator.AAGUID,
		Transports:     joinTransports(c.Transport),
		BackupEligible: c.Flags.BackupEligible,
		BackupState:    c.Flags.BackupState,
	}
}

// parseTransports turns the stored comma-joined transports string into the
// typed slice go-webauthn expects ("" → nil).
func parseTransports(s string) []protocol.AuthenticatorTransport {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]protocol.AuthenticatorTransport, 0, len(parts))
	for _, p := range parts {
		out = append(out, protocol.AuthenticatorTransport(p))
	}
	return out
}

// joinTransports renders a transports slice back to the stored comma-joined
// string (nil/empty → "").
func joinTransports(ts []protocol.AuthenticatorTransport) string {
	if len(ts) == 0 {
		return ""
	}
	parts := make([]string, len(ts))
	for i, t := range ts {
		parts[i] = string(t)
	}
	return strings.Join(parts, ",")
}
