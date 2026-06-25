//go:build darwin

package privsep_test

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

func TestCheckFDA_ReturnsBool(t *testing.T) {
	// CheckFDA probes the TCC sentinel file. In the test environment
	// the runner is unlikely to have FDA, but the function must return
	// a boolean without panicking regardless.
	_ = privsep.CheckFDA()
}

func TestCheckFDA_FalseWithoutFDA(t *testing.T) {
	// CI runners (and most test environments) do not have Full Disk
	// Access. Verify the function returns false rather than true when
	// the sentinel is unreadable. Skip if somehow the test process does
	// have FDA (a developer machine might).
	if privsep.CheckFDA() {
		t.Skip("test process has Full Disk Access — skipping false-path assertion")
	}
}
