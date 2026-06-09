package machineid

import (
	"bytes"
	"errors"
	"testing"
)

func TestID_StableAnd32Bytes(t *testing.T) {
	id1, err := ID()
	if errors.Is(err, ErrUnavailable) {
		t.Skip("no stable machine id on this host")
	}
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	if len(id1) != 32 {
		t.Fatalf("len = %d, want 32", len(id1))
	}
	id2, err := ID()
	if err != nil {
		t.Fatalf("ID (2nd call): %v", err)
	}
	if !bytes.Equal(id1, id2) {
		t.Fatal("ID is not stable across calls")
	}
}
