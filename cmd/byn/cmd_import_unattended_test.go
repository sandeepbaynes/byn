package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestImportUnattended_RejectsFileFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--unattended", "--format", "env"},
		{"--unattended", "--replace"},
		{"--unattended", "--skip-existing"},
		{"--unattended", "--all", "API_KEY"},
		{"--all"},
	} {
		var rc int
		captureStderr(t, func() { rc = runImport(args, cliScope{}) })
		if rc != exitErr {
			t.Fatalf("%v: rc = %d, want exitErr", args, rc)
		}
	}
}

func TestImportUnattended_DryRunSendsNoPassword(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpUnattendedImport, ipc.UnattendedImportResp{
		Imported: []ipc.UnattendedItem{{Project: "monorepo", Env: "default", Name: "AUTH_KEY"}},
	})
	var rc int
	var out string
	errOut := captureStderr(t, func() {
		out = captureStdout(t, func() { rc = runImport([]string{"--unattended", "--dry-run"}, cliScope{Env: "default"}) })
	})
	if rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out, "monorepo/default AUTH_KEY") || !strings.Contains(errOut, "Would import 1") {
		t.Fatalf("stdout=%q stderr=%q", out, errOut)
	}
	calls := fd.callsFor(ipc.OpUnattendedImport)
	if len(calls) != 1 {
		t.Fatalf("calls = %d", len(calls))
	}
	var req ipc.UnattendedImportReq
	if err := json.Unmarshal(calls[0].Body, &req); err != nil {
		t.Fatal(err)
	}
	if !req.DryRun || len(req.Password) != 0 {
		t.Fatalf("req = %+v", req)
	}
}

func TestImportUnattended_AllAndNamesReachTheDaemon(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpUnattendedImport, ipc.UnattendedImportResp{
		Imported: []ipc.UnattendedItem{{Project: "p", Env: "default", Name: "A"}},
		Skipped:  []ipc.UnattendedSkip{{Name: "B", Reason: "inherited from default — import it there: --env default"}},
	})
	var rc int
	errOut := captureStderr(t, func() {
		captureStdout(t, func() { rc = runImport([]string{"--unattended", "A", "B"}, cliScope{}) })
	})
	if rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(errOut, "skipped B: inherited from default") || !strings.Contains(errOut, "Imported 1") {
		t.Fatalf("stderr = %q", errOut)
	}
	var req ipc.UnattendedImportReq
	if err := json.Unmarshal(fd.callsFor(ipc.OpUnattendedImport)[0].Body, &req); err != nil {
		t.Fatal(err)
	}
	if strings.Join(req.Names, ",") != "A,B" || req.All {
		t.Fatalf("req = %+v", req)
	}
}

func TestImportUnattended_OnlySkipsIsAFailure(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpUnattendedImport, ipc.UnattendedImportResp{
		Skipped: []ipc.UnattendedSkip{{Name: "NOPE", Reason: "not an unattended value in p/default"}},
	})
	var rc int
	captureStderr(t, func() { rc = runImport([]string{"--unattended", "NOPE"}, cliScope{}) })
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr when nothing asked for could be imported", rc)
	}
}

func TestImportUnattended_NothingToDo(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpUnattendedImport, ipc.UnattendedImportResp{})
	var rc int
	errOut := captureStderr(t, func() { rc = runImport([]string{"--unattended"}, cliScope{}) })
	if rc != exitOK || !strings.Contains(errOut, "already protected") {
		t.Fatalf("rc=%d stderr=%q", rc, errOut)
	}
}

func TestImportUnattended_DaemonErrorIsReported(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpUnattendedImport, ipc.CodeInternal, "boom")
	var rc int
	captureStderr(t, func() { rc = runImport([]string{"--unattended", "--dry-run"}, cliScope{}) })
	if rc == exitOK {
		t.Fatal("a daemon error must not exit 0")
	}
}

func TestImportEnvHint(t *testing.T) {
	inherited := []ipc.SecretMeta{{Name: "A", Unattended: true, UnattendedInherited: true}, {Name: "B"}}
	if got := importEnvHint(inherited); got != " --env default" {
		t.Fatalf("all inherited: %q", got)
	}
	mixed := append(append([]ipc.SecretMeta{}, inherited...), ipc.SecretMeta{Name: "C", Unattended: true})
	if got := importEnvHint(mixed); got != "" {
		t.Fatalf("own value present: %q", got)
	}
}

func TestRenderMissingValues_SeparatesPresentButUnreachable(t *testing.T) {
	out := captureStderr(t, func() {
		renderMissingValues([]string{
			"GONE",
			"AUTH_KEY (stored unattended in default — run: byn import --unattended --env default)",
		}, nil, ".byn")
	})
	if !strings.Contains(out, "AUTH_KEY is in the vault but was not injected (stored unattended in default") {
		t.Fatalf("unreachable line missing: %q", out)
	}
	if !strings.Contains(out, "1 variable(s) the vault has no value for: GONE") {
		t.Fatalf("absent line wrong: %q", out)
	}
	if strings.Contains(out, "no value for: GONE, AUTH_KEY") {
		t.Fatal("a present value must not be reported as having no value")
	}
}

func TestRunList_LongMarksInheritedUnattendedAndPointsAtImport(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{
		{Name: "AUTH_KEY", Unattended: true, UnattendedInherited: true},
		{Name: "SEED"},
	}})
	var out string
	errOut := captureStderr(t, func() {
		out = captureStdout(t, func() { runList([]string{"--long"}, cliScope{Env: "prod"}) })
	})
	if !strings.Contains(out, "AUTH_KEY") || !strings.Contains(out, "inherited from default") {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(errOut, "byn import --unattended --env default") {
		t.Fatalf("stderr = %q, want the import command", errOut)
	}
}

func TestPluralThem(t *testing.T) {
	if pluralThem(1) != "it" || pluralThem(2) != "them" {
		t.Fatal("pluralThem")
	}
}
