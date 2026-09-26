package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// ---- parsing ----------------------------------------------------------------

func parseOne(t *testing.T, body string) []kv {
	t.Helper()
	got, err := parseDotenv([]byte(body))
	if err != nil {
		t.Fatalf("parseDotenv: %v", err)
	}
	return got
}

func TestParseDotenv_DescriptionAndNotes(t *testing.T) {
	got := parseOne(t, "# the staging key\n## acct 1234\n## rotated in May\nAPI_KEY=abc\nPLAIN=1\n")
	if len(got) != 2 {
		t.Fatalf("got %d entries", len(got))
	}
	want := entryAnnotations{desc: "the staging key", notes: []string{"acct 1234", "rotated in May"}}
	if !reflect.DeepEqual(got[0].ann, want) {
		t.Fatalf("ann = %+v, want %+v", got[0].ann, want)
	}
	if !got[1].ann.empty() {
		t.Fatalf("PLAIN picked up %+v — a block belongs to one variable", got[1].ann)
	}
}

func TestParseDotenv_SeveralHashLinesAreOneDescription(t *testing.T) {
	got := parseOne(t, "# line one\n#\n#   indented\n# line three\nK=v\n")
	if got[0].ann.desc != "line one\n\n  indented\nline three" {
		t.Fatalf("desc = %q", got[0].ann.desc)
	}
	if len(got[0].ann.notes) != 0 {
		t.Fatalf("notes = %q", got[0].ann.notes)
	}
}

func TestParseDotenv_HashAfterNoteIsDropped(t *testing.T) {
	got := parseOne(t, "# desc\n## note one\n# stray\n## note two\nK=v\n")
	want := entryAnnotations{desc: "desc", notes: []string{"note one", "note two"}}
	if !reflect.DeepEqual(got[0].ann, want) {
		t.Fatalf("ann = %+v, want %+v", got[0].ann, want)
	}
}

func TestParseDotenv_TripleHashIsANote(t *testing.T) {
	got := parseOne(t, "### a note\n##no space\n##\nK=v\n")
	if !reflect.DeepEqual(got[0].ann.notes, []string{"a note", "no space"}) {
		t.Fatalf("notes = %q (an empty ## line adds nothing)", got[0].ann.notes)
	}
}

func TestParseDotenv_BlankLineEndsTheBlock(t *testing.T) {
	got := parseOne(t, "# Database settings\n\nDB_URL=x\n")
	if !got[0].ann.empty() {
		t.Fatalf("a heading separated by a blank line attached: %+v", got[0].ann)
	}
}

// A commented-out variable often holds an old secret. It must never become a
// description, which is plaintext any tool can read, and the comments above
// it were about it, so they do not carry on to the next variable either.
func TestParseDotenv_CommentedOutAssignmentIsNotADescription(t *testing.T) {
	for _, line := range []string{"# OLD_KEY=sk_live_123", "#export OLD_KEY=x", "# app.port = 80"} {
		got := parseOne(t, "# about the old key\n"+line+"\nNEW_KEY=v\n")
		if !got[0].ann.empty() {
			t.Errorf("%q: ann = %+v, want none", line, got[0].ann)
		}
	}
	// Prose with an equals sign later on is still a description.
	got := parseOne(t, "# set to 1 when a=b\nK=v\n")
	if got[0].ann.desc != "set to 1 when a=b" {
		t.Fatalf("desc = %q", got[0].ann.desc)
	}
}

func TestParseDotenv_NotesWithoutDescription(t *testing.T) {
	got := parseOne(t, "## only a note\nK=v\n")
	if got[0].ann.desc != "" || !reflect.DeepEqual(got[0].ann.notes, []string{"only a note"}) {
		t.Fatalf("ann = %+v", got[0].ann)
	}
}

// ---- rendering --------------------------------------------------------------

func TestRenderDotenvAnnotated_Format(t *testing.T) {
	out := renderDotenvAnnotated(
		[]string{"A", "B", "C"},
		map[string]string{"A": "1", "B": "2", "C": "3"},
		map[string]entryAnnotations{
			"B": {desc: "first\n\nthird  ", notes: []string{"one", "two\nlines", "   "}},
		})
	want := "A=1\n\n# first\n#\n# third\n## one\n## two lines\nB=2\nC=3\n"
	if out != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
}

func TestRenderDotenvAnnotated_FirstEntryHasNoLeadingBlank(t *testing.T) {
	out := renderDotenvAnnotated([]string{"A"}, map[string]string{"A": "1"},
		map[string]entryAnnotations{"A": {desc: "d"}})
	if out != "# d\nA=1\n" {
		t.Fatalf("got %q", out)
	}
}

func TestDotenvAnnotations_RoundTrip(t *testing.T) {
	ann := map[string]entryAnnotations{
		"API_KEY": {desc: "staging only\n# not a heading", notes: []string{"acct 1234", "#tagged"}},
		"DB_URL":  {notes: []string{"read replica"}},
	}
	keys := []string{"API_KEY", "DB_URL", "PLAIN"}
	vals := map[string]string{"API_KEY": "abc", "DB_URL": "postgres://x", "PLAIN": "p"}
	got := parseOne(t, renderDotenvAnnotated(keys, vals, ann))
	if len(got) != 3 {
		t.Fatalf("got %d entries", len(got))
	}
	for _, e := range got {
		if !reflect.DeepEqual(e.ann, ann[e.k]) && (!e.ann.empty() || !ann[e.k].empty()) {
			t.Errorf("%s: ann = %+v, want %+v", e.k, e.ann, ann[e.k])
		}
		if e.v != vals[e.k] {
			t.Errorf("%s: value = %q", e.k, e.v)
		}
	}
}

func TestAnnotationSummary(t *testing.T) {
	cases := map[string]entryAnnotations{
		"":                        {},
		" + description":          {desc: "d"},
		" + 1 note":               {notes: []string{"n"}},
		" + description, 2 notes": {desc: "d", notes: []string{"a", "b"}},
	}
	for want, a := range cases {
		if got := annotationSummary(a); got != want {
			t.Errorf("annotationSummary(%+v) = %q, want %q", a, got, want)
		}
	}
}

// ---- import -----------------------------------------------------------------

// registerAnnotationCapture records notes added and optionally serves a list of
// existing ones. authFirst makes the first password-less add answer
// auth_required.
func registerAnnotationCapture(fd *fakeDaemon, existing []string, authFirst bool) *[]ipc.AnnotationAddReq {
	var added []ipc.AnnotationAddReq
	fd.on(ipc.OpAnnotationAdd, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.AnnotationAddReq
		_ = json.Unmarshal(raw, &req)
		if authFirst && len(req.Password) == 0 {
			return nil, &ipc.ErrMsg{Code: ipc.CodeAuthRequired, Message: "auth required"}
		}
		added = append(added, req)
		return ipc.AnnotationAddResp{ID: int64(len(added))}, nil
	})
	fd.on(ipc.OpAnnotationList, func([]byte) (any, *ipc.ErrMsg) {
		var views []ipc.AnnotationView
		for _, b := range existing {
			views = append(views, ipc.AnnotationView{Kind: "note", Body: b})
		}
		return ipc.AnnotationListResp{Notes: views, NoteCount: len(views)}, nil
	})
	return &added
}

func writeEnvFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.env")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunImport_AppliesDescriptionAndNotes(t *testing.T) {
	fd := startFakeDaemon(t)
	registerPutCounter(fd, "", nil)
	fd.onOK(ipc.OpList, ipc.ListResp{})
	added := registerAnnotationCapture(fd, nil, false)

	path := writeEnvFile(t, "# the staging key\n## acct 1234\n## rotated\nAPI_KEY=abc\nPLAIN=1\n")
	if rc := runImport([]string{path}, cliScope{Env: "prod"}); rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	var descs = map[string]string{}
	for _, c := range fd.callsFor(ipc.OpPut) {
		var req ipc.PutReq
		requireUnmarshal(t, c.Body, &req)
		descs[req.Name] = req.Description
		if req.Note != "" {
			t.Errorf("%s: notes go through annotation add, not the put", req.Name)
		}
	}
	if descs["API_KEY"] != "the staging key" || descs["PLAIN"] != "" {
		t.Fatalf("put descriptions = %q", descs)
	}
	if len(*added) != 2 || (*added)[0].Text != "acct 1234" || (*added)[1].Text != "rotated" {
		t.Fatalf("notes added = %+v", *added)
	}
	if (*added)[0].Target.Name != "API_KEY" || (*added)[0].Target.Type != "entry" || (*added)[0].Scope.Env != "prod" {
		t.Fatalf("note target = %+v scope = %+v", (*added)[0].Target, (*added)[0].Scope)
	}
}

// Importing the same file twice must leave one copy of everything.
func TestRunImport_ReimportAddsNothingNew(t *testing.T) {
	fd := startFakeDaemon(t)
	registerPutCounter(fd, "", nil)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{
		{Name: "API_KEY", Source: "scope", Description: "the staging key", Notes: 1},
	}})
	added := registerAnnotationCapture(fd, []string{"acct 1234"}, false)

	path := writeEnvFile(t, "# the staging key\n## acct 1234\n## new one\nAPI_KEY=abc\n")
	if rc := runImport([]string{path}, cliScope{}); rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	var req ipc.PutReq
	requireUnmarshal(t, fd.callsFor(ipc.OpPut)[0].Body, &req)
	if req.Description != "" {
		t.Fatalf("unchanged description re-sent: %q", req.Description)
	}
	if len(*added) != 1 || (*added)[0].Text != "new one" {
		t.Fatalf("notes added = %+v, want only the new one", *added)
	}
}

// A description a trusted .byn declares is not the vault's own; matching it
// does not mean the vault already has it.
func TestRunImport_BynDescriptionDoesNotCountAsStored(t *testing.T) {
	fd := startFakeDaemon(t)
	registerPutCounter(fd, "", nil)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{
		{Name: "K", Source: "scope", Description: "d", DescriptionSource: ".byn"},
	}})
	path := writeEnvFile(t, "# d\nK=v\n")
	if rc := runImport([]string{path}, cliScope{}); rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	var req ipc.PutReq
	requireUnmarshal(t, fd.callsFor(ipc.OpPut)[0].Body, &req)
	if req.Description != "d" {
		t.Fatalf("description = %q, want it written to the vault", req.Description)
	}
}

func TestRunImport_UnannotatedFileSkipsTheListCall(t *testing.T) {
	fd := startFakeDaemon(t)
	registerPutCounter(fd, "", nil)
	if rc := runImport([]string{writeEnvFile(t, "A=1\n")}, cliScope{}); rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	if n := len(fd.callsFor(ipc.OpList)); n != 0 {
		t.Fatalf("list called %d times for a file with no comments", n)
	}
}

func TestRunImport_NoteAuthRequiredUsesPasswordStdin(t *testing.T) {
	fd := startFakeDaemon(t)
	registerPutCounter(fd, "", nil)
	fd.onOK(ipc.OpList, ipc.ListResp{})
	added := registerAnnotationCapture(fd, nil, true)

	withStdin(t, "hunter2")
	// Stdin carries the password; the file comes from a path.
	path := writeEnvFile(t, "## n\nK=v\n")
	if rc := runImport([]string{path, "--password-stdin"}, cliScope{}); rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	if len(*added) != 1 || strings.TrimSpace(string((*added)[0].Password)) != "hunter2" {
		t.Fatalf("notes added = %+v", *added)
	}
}

func TestRunImport_NoteErrorFails(t *testing.T) {
	fd := startFakeDaemon(t)
	registerPutCounter(fd, "", nil)
	fd.onOK(ipc.OpList, ipc.ListResp{})
	fd.onErr(ipc.OpAnnotationAdd, ipc.CodeInternal, "boom")
	if rc := runImport([]string{writeEnvFile(t, "## n\nK=v\n")}, cliScope{}); rc != exitErr {
		t.Fatalf("rc = %d, want exitErr", rc)
	}
}

func TestRunImport_ExistingNotesListErrorFails(t *testing.T) {
	fd := startFakeDaemon(t)
	registerPutCounter(fd, "", nil)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{{Name: "K", Source: "scope", Notes: 2}}})
	fd.onErr(ipc.OpAnnotationList, ipc.CodeLocked, "locked")
	if rc := runImport([]string{writeEnvFile(t, "## n\nK=v\n")}, cliScope{}); rc != exitErr {
		t.Fatalf("rc = %d, want exitErr", rc)
	}
}

func TestRunImport_SkippedExistingGetsNoNotes(t *testing.T) {
	fd := startFakeDaemon(t)
	registerPutCounter(fd, "K", &ipc.ErrMsg{Code: ipc.CodeAlreadyExists, Message: "exists"})
	fd.onOK(ipc.OpList, ipc.ListResp{})
	added := registerAnnotationCapture(fd, nil, false)
	if rc := runImport([]string{writeEnvFile(t, "## n\nK=v\n"), "--skip-existing"}, cliScope{}); rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	if len(*added) != 0 {
		t.Fatalf("a skipped value got notes: %+v", *added)
	}
}

func TestRunImport_DryRunNamesAnnotationsNotTheirText(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{})
	out := captureStdout(t, func() {
		if rc := runImport([]string{writeEnvFile(t, "# d\n## secret acct 1234\n## b\nK=v\n"), "--dry-run"}, cliScope{}); rc != exitOK {
			t.Errorf("rc = %d", rc)
		}
	})
	if !strings.Contains(out, "+ K = (1 bytes) + description, 2 notes") {
		t.Fatalf("dry-run = %q", out)
	}
	if strings.Contains(out, "acct 1234") {
		t.Fatalf("dry-run printed a note's text: %q", out)
	}
}

// ---- export -----------------------------------------------------------------

func TestRunExport_WritesDescriptionsAndNotes(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{
		{Name: "A", Description: "plain"},
		{Name: "B", Description: "from the manifest", DescriptionSource: ".byn"},
		{Name: "C", Source: "default", Notes: 2},
	}})
	fd.on(ipc.OpGet, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.GetReq
		_ = json.Unmarshal(raw, &req)
		return ipc.GetResp{Name: req.Name, Value: []byte("v")}, nil
	})
	var listScope ipc.Scope
	fd.on(ipc.OpAnnotationList, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.AnnotationListReq
		_ = json.Unmarshal(raw, &req)
		listScope = req.Scope
		if req.Kind != "note" || req.Target.Name != "C" {
			return nil, &ipc.ErrMsg{Code: ipc.CodeInternal, Message: "unexpected list"}
		}
		return ipc.AnnotationListResp{Notes: []ipc.AnnotationView{{Body: "n1"}, {Body: "n2"}}}, nil
	})
	out := captureStdout(t, func() {
		if rc := runExport(nil, cliScope{Env: "prod"}); rc != exitOK {
			t.Errorf("rc = %d", rc)
		}
	})
	want := "# plain\nA=v\nB=v\n\n## n1\n## n2\nC=v\n"
	if out != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
	if listScope.Env != "default" {
		t.Fatalf("an inherited value's notes were read from env %q, want default", listScope.Env)
	}
}

func TestRunExport_JSONReadsNoNotes(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{{Name: "A", Notes: 1}}})
	fd.onOK(ipc.OpGet, ipc.GetResp{Name: "A", Value: []byte("1")})
	_ = captureStdout(t, func() {
		if rc := runExport([]string{"--format=json"}, cliScope{}); rc != exitOK {
			t.Errorf("rc = %d", rc)
		}
	})
	if n := len(fd.callsFor(ipc.OpAnnotationList)); n != 0 {
		t.Fatalf("json export read notes %d times", n)
	}
}

func TestRunExport_NotesAuthRequiredPromptsOnce(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{{Name: "A", Notes: 1}}})
	fd.onOK(ipc.OpGet, ipc.GetResp{Name: "A", Value: []byte("1")})
	fd.on(ipc.OpAnnotationList, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.AnnotationListReq
		_ = json.Unmarshal(raw, &req)
		if len(req.Password) == 0 {
			return nil, &ipc.ErrMsg{Code: ipc.CodeAuthRequired, Message: "auth required"}
		}
		return ipc.AnnotationListResp{Notes: []ipc.AnnotationView{{Body: "n"}}}, nil
	})
	withStdin(t, "hunter2\n")
	out := captureStdout(t, func() {
		if rc := runExport([]string{"--password-stdin"}, cliScope{}); rc != exitOK {
			t.Errorf("rc = %d", rc)
		}
	})
	if out != "## n\nA=1\n" {
		t.Fatalf("got %q", out)
	}
}

func TestRunExport_NotesErrorFails(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{{Name: "A", Notes: 1}}})
	fd.onOK(ipc.OpGet, ipc.GetResp{Name: "A", Value: []byte("1")})
	fd.onErr(ipc.OpAnnotationList, ipc.CodeLocked, "locked")
	if rc := runExport(nil, cliScope{}); rc != exitDaemonErr {
		t.Fatalf("rc = %d, want exitDaemonErr", rc)
	}
}

// With no terminal and no --password-stdin, a note that needs authorization
// fails the import rather than being dropped quietly.
func TestRunImport_NoteAuthRequiredWithoutPasswordFails(t *testing.T) {
	fd := startFakeDaemon(t)
	registerPutCounter(fd, "", nil)
	fd.onOK(ipc.OpList, ipc.ListResp{})
	added := registerAnnotationCapture(fd, nil, true)
	withStdin(t, "")
	if rc := runImport([]string{writeEnvFile(t, "## n\nK=v\n")}, cliScope{}); rc != exitErr {
		t.Fatalf("rc = %d, want exitErr", rc)
	}
	if len(*added) != 0 {
		t.Fatalf("notes added = %+v", *added)
	}
}
