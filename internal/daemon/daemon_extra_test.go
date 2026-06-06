package daemon

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestWait_ReturnsAfterShutdown(t *testing.T) {
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.Wait()
	}()
	d.Shutdown(2 * time.Second)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Wait did not return")
	}
}

func TestRemoveVault_Idempotent(t *testing.T) {
	// removeVault is currently //nolint:unused but logically idempotent;
	// exercise it directly via the package-internal API.
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Removing a never-opened vault is a no-op.
	d.removeVault("never-opened")
}
