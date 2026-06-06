package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSortStrings_Behavior(t *testing.T) {
	in := []string{"c", "a", "b"}
	sortStrings(in)
	if strings.Join(in, ",") != "a,b,c" {
		t.Fatalf("got %v", in)
	}
	// Already sorted is a noop.
	already := []string{"a", "b", "c"}
	sortStrings(already)
	if strings.Join(already, ",") != "a,b,c" {
		t.Fatalf("got %v", already)
	}
	// Reverse sorts.
	rev := []string{"e", "d", "c", "b", "a"}
	sortStrings(rev)
	if strings.Join(rev, ",") != "a,b,c,d,e" {
		t.Fatalf("got %v", rev)
	}
	// Empty / single elt.
	var empty []string
	sortStrings(empty)
	one := []string{"x"}
	sortStrings(one)
}

func TestSplitLines_NoTrailingNewline(t *testing.T) {
	got := splitLines([]byte("a\nb\nc"))
	if len(got) != 3 || string(got[2]) != "c" {
		t.Fatalf("got %v", got)
	}
}

func TestSplitLines_OnlyNewlines(t *testing.T) {
	got := splitLines([]byte("\n\n"))
	if len(got) != 2 {
		t.Fatalf("got %d, want 2 empty lines", len(got))
	}
}

func TestSplitLines_Empty(t *testing.T) {
	got := splitLines(nil)
	if len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestHead_EmptyOnFreshLogger(t *testing.T) {
	l, _, _ := freshLogger(t)
	if got := l.Head(); got != "" {
		t.Fatalf("Head=%q on fresh logger", got)
	}
}

func TestHead_AfterAppend(t *testing.T) {
	l, _, _ := freshLogger(t)
	head, err := l.Append(context.Background(), Event{Op: "x", Outcome: OutcomeOK})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if l.Head() != head {
		t.Fatalf("Head() = %q, want %q", l.Head(), head)
	}
}

func TestNew_EmptyVaultIDOrName(t *testing.T) {
	var seed [32]byte
	_, _ = rand.Read(seed[:])
	store := newFakeStore(seed[:])
	if _, err := New(context.Background(), t.TempDir(), "", "name", store); err == nil {
		t.Fatal("expected err for empty vid")
	}
	if _, err := New(context.Background(), t.TempDir(), "vid", "", store); err == nil {
		t.Fatal("expected err for empty name")
	}
}

func TestNew_NilStore(t *testing.T) {
	if _, err := New(context.Background(), t.TempDir(), "vid", "name", nil); err == nil {
		t.Fatal("expected err for nil store")
	}
}

func TestNew_LoadsExistingHead(t *testing.T) {
	var seed [32]byte
	_, _ = rand.Read(seed[:])
	store := newFakeStore(seed[:])
	store.data[MetaKeyHead] = "deadbeef"
	l, err := New(context.Background(), t.TempDir(), "vid", "name", store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if l.Head() != "deadbeef" {
		t.Fatalf("Head=%q", l.Head())
	}
}

func TestNew_BadSeedHex(t *testing.T) {
	store := &fakeStore{data: map[string]string{MetaKeySeed: "not_hex_zz"}}
	if _, err := New(context.Background(), t.TempDir(), "vid", "name", store); err == nil {
		t.Fatal("expected bad-seed err")
	}
}

func TestNew_WrongSeedLength(t *testing.T) {
	// 16 bytes = too short.
	store := &fakeStore{data: map[string]string{MetaKeySeed: hex.EncodeToString(make([]byte, 16))}}
	if _, err := New(context.Background(), t.TempDir(), "vid", "name", store); err == nil {
		t.Fatal("expected bad-seed-length err")
	}
}

func TestComputeChain_BadPrevHex(t *testing.T) {
	l, _, _ := freshLogger(t)
	l.prevHex = "zz-bad-hex"
	_, err := l.computeChain(Event{Op: "x"})
	if err == nil {
		t.Fatal("expected err for bad prev hex")
	}
}
