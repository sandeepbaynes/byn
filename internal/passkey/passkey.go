// Package passkey is byn's WebAuthn relying party for the browser portal.
//
// rp.id is fixed to "localhost" — chosen by the PRF spike (see
// docs/research/webauthn-prf-spike.md) and kept stable forever: moving the
// portal off localhost would orphan every enrolled passkey. This slice
// (A-auth.1) covers the session-auth ceremonies; PRF-based cold vault-unlock
// is A-auth.2.
package passkey

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// RPID is the WebAuthn Relying Party ID. Stable forever — see the package doc.
const RPID = "localhost"

// New builds the relying party for a portal served at the given loopback
// origin (e.g. "http://localhost:2967"). http://localhost is a browser secure
// context, so WebAuthn works without TLS.
func New(origin string) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          RPID,
		RPDisplayName: "byn",
		RPOrigins:     []string{origin},
	})
}

// User is the WebAuthn "user" for a single vault. ID is a stable per-vault
// handle (the vault id); Creds are the vault's enrolled credentials, which the
// caller loads from the vault's passkey store and converts to
// webauthn.Credential via ToCredential.
type User struct {
	ID    []byte
	Name  string
	Creds []webauthn.Credential
}

// WebAuthnID implements webauthn.User.
func (u *User) WebAuthnID() []byte { return u.ID }

// WebAuthnName implements webauthn.User.
func (u *User) WebAuthnName() string { return u.Name }

// WebAuthnDisplayName implements webauthn.User.
func (u *User) WebAuthnDisplayName() string { return u.Name }

// WebAuthnCredentials implements webauthn.User.
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Creds }

// BeginRegistration starts enrollment of a new credential for the user. The
// returned options go to the browser (navigator.credentials.create); the
// SessionData (challenge) MUST be persisted server-side and handed back to
// FinishRegistration to bind the response to this challenge.
func BeginRegistration(rp *webauthn.WebAuthn, u *User) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return rp.BeginRegistration(u)
}
