package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// everything written to stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	fn()
	_ = w.Close()
	os.Stdout = old
	return <-done
}

func seedList(t *testing.T, names ...string) *fakeDaemon {
	t.Helper()
	fd := startFakeDaemon(t)
	metas := make([]ipc.SecretMeta, 0, len(names))
	for _, n := range names {
		metas = append(metas, ipc.SecretMeta{Name: n})
	}
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: metas})
	return fd
}

func TestRunList_ExactMatch_Found(t *testing.T) {
	seedList(t, "A", "SQL_POOL_MAX", "B")
	var rc int
	out := captureStdout(t, func() { rc = runList([]string{"SQL_POOL_MAX"}, cliScope{}) })
	if rc != exitOK {
		t.Fatalf("rc = %d, want exitOK", rc)
	}
	if strings.TrimSpace(out) != "SQL_POOL_MAX" {
		t.Fatalf("stdout = %q, want SQL_POOL_MAX", out)
	}
}

func TestRunList_ExactMatch_NotFound(t *testing.T) {
	seedList(t, "A", "B")
	var rc int
	out := captureStdout(t, func() { rc = runList([]string{"NOPE"}, cliScope{}) })
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr (no match)", rc)
	}
	if out != "" {
		t.Fatalf("stdout = %q, want empty on no match", out)
	}
}

func TestRunList_Glob(t *testing.T) {
	seedList(t, "SQL_A", "SQL_B", "OTHER", "PSQL")
	var rc int
	out := captureStdout(t, func() { rc = runList([]string{"SQL*"}, cliScope{}) })
	if rc != exitOK {
		t.Fatalf("rc = %d, want exitOK", rc)
	}
	lines := strings.Fields(out)
	if len(lines) != 2 || lines[0] != "SQL_A" || lines[1] != "SQL_B" {
		t.Fatalf("glob output = %q, want SQL_A SQL_B", out)
	}
}

func TestRunList_Glob_Question(t *testing.T) {
	seedList(t, "DB1", "DB2", "DBXX")
	var rc int
	out := captureStdout(t, func() { rc = runList([]string{"DB?"}, cliScope{}) })
	if rc != exitOK {
		t.Fatalf("rc = %d, want exitOK", rc)
	}
	if got := strings.Fields(out); len(got) != 2 {
		t.Fatalf("DB? matched %v, want 2 (DB1, DB2)", got)
	}
}

func TestRunList_BadPattern(t *testing.T) {
	// No daemon needed: the bad glob fails before any IPC call.
	noDaemon(t)
	if rc := runList([]string{"["}, cliScope{}); rc != exitErr {
		t.Fatalf("rc = %d, want exitErr for a bad pattern", rc)
	}
}

func TestRunList_TooManyArgs(t *testing.T) {
	noDaemon(t)
	if rc := runList([]string{"a", "b"}, cliScope{}); rc != exitErr {
		t.Fatalf("rc = %d, want exitErr", rc)
	}
}

func TestRunList_PatternJSON_NoMatch(t *testing.T) {
	seedList(t, "A")
	var rc int
	out := captureStdout(t, func() { rc = runList([]string{"--json", "NOPE"}, cliScope{}) })
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr (no match)", rc)
	}
	if strings.TrimSpace(out) != "[]" {
		t.Fatalf("json no-match stdout = %q, want []", out)
	}
}
