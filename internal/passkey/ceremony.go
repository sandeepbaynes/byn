package passkey

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// BeginLogin starts an assertion (login / unlock) ceremony for the user. The
// options go to the browser (navigator.credentials.get); the SessionData
// (challenge) MUST be persisted server-side and handed back to FinishLogin so
// the response is bound to this challenge.
func BeginLogin(rp *webauthn.WebAuthn, u *User) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return rp.BeginLogin(u)
}

// FinishRegistration verifies the browser's attestation response against the
// stored challenge and returns the new credential to persist. Takes raw JSON
// because the daemon has no *http.Request (the portal forwards the body over
// IPC); origin/RP-ID are still validated from the embedded clientDataJSON.
func FinishRegistration(rp *webauthn.WebAuthn, u *User, sess *webauthn.SessionData, responseJSON []byte) (*webauthn.Credential, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(responseJSON)
	if err != nil {
		return nil, err
	}
	return rp.CreateCredential(u, *sess, parsed)
}

// FinishLogin verifies the browser's assertion response against the stored
// challenge and returns the matched credential with its updated sign counter.
// Raw JSON, same rationale as FinishRegistration.
func FinishLogin(rp *webauthn.WebAuthn, u *User, sess *webauthn.SessionData, responseJSON []byte) (*webauthn.Credential, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(responseJSON)
	if err != nil {
		return nil, err
	}
	return rp.ValidateLogin(u, *sess, parsed)
}
