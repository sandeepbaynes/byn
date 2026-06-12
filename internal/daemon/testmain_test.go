package daemon

import (
	"os"
	"testing"

	"github.com/sandeepbaynes/byn/internal/vault"
	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// TestMain lowers the vault KDF cost for the whole package. NU-3 added
// many real vault.Init/unlock calls across the daemon tests; at
// production Argon2 cost (~1s/op) the cumulative spend under -race blows
// the package test timeout on slow CI runners (macOS arm64). The
// lowered params only affect the store-level wrap default — production
// binaries still use vcrypto.DefaultArgon2Params.
func TestMain(m *testing.M) {
	vault.SetKDFParamsForTesting(vcrypto.TestArgon2Params)
	os.Exit(m.Run())
}
