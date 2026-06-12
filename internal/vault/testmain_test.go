package vault

import (
	"os"
	"testing"

	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// TestMain lowers the vault KDF cost for the whole package so the many
// real Init/Unlock/ChangePassword calls don't each pay the ~1s
// production Argon2 cost (which blows the -race package timeout on slow
// CI runners). The crypto package's own Wrap/Unwrap tests are
// unaffected: they pass explicit params and never read this var.
func TestMain(m *testing.M) {
	SetKDFParamsForTesting(vcrypto.TestArgon2Params)
	os.Exit(m.Run())
}
