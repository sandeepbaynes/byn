package passkey

import (
	"bytes"
	"testing"

	"github.com/sandeepbaynes/byn/internal/vault"
)

func TestCredentialRoundTrip(t *testing.T) {
	pk := vault.Passkey{
		CredentialID:   []byte{1, 2, 3, 4},
		PublicKey:      []byte("cose-public-key"),
		SignCount:      11,
		AAGUID:         []byte{9, 8, 7},
		Transports:     "internal,hybrid",
		BackupEligible: true,
		BackupState:    true,
	}
	c := ToCredential(pk)
	if !bytes.Equal(c.ID, pk.CredentialID) || !bytes.Equal(c.PublicKey, pk.PublicKey) {
		t.Fatal("id/public key not carried into webauthn.Credential")
	}
	if c.Authenticator.SignCount != 11 || !bytes.Equal(c.Authenticator.AAGUID, pk.AAGUID) {
		t.Fatalf("authenticator fields lost: %+v", c.Authenticator)
	}
	if !c.Flags.BackupEligible || !c.Flags.BackupState {
		t.Fatalf("backup flags not carried into credential: %+v", c.Flags)
	}
	if len(c.Transport) != 2 || string(c.Transport[0]) != "internal" || string(c.Transport[1]) != "hybrid" {
		t.Fatalf("transports not parsed: %+v", c.Transport)
	}

	back := FromCredential(c)
	if !bytes.Equal(back.CredentialID, pk.CredentialID) || !bytes.Equal(back.PublicKey, pk.PublicKey) ||
		back.SignCount != pk.SignCount || !bytes.Equal(back.AAGUID, pk.AAGUID) || back.Transports != pk.Transports ||
		back.BackupEligible != pk.BackupEligible || back.BackupState != pk.BackupState {
		t.Fatalf("round-trip mismatch:\n in:  %+v\n out: %+v", pk, back)
	}
}

func TestCredential_EmptyTransports(t *testing.T) {
	c := ToCredential(vault.Passkey{CredentialID: []byte{1}, PublicKey: []byte("k")})
	if len(c.Transport) != 0 {
		t.Fatalf("empty transports should yield no entries, got %+v", c.Transport)
	}
	if back := FromCredential(c); back.Transports != "" {
		t.Fatalf("empty transports should round-trip to \"\", got %q", back.Transports)
	}
}
