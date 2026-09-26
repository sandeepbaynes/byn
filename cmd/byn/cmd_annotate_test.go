package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// ---- target parsing ----------------------------------------------------

func TestParseTarget(t *testing.T) {
	for _, tc := range []struct {
		in   string
		typ  string
		name string
		id   int64
	}{
		{"API_KEY", "entry", "API_KEY", 0},
		{"entry:API_KEY", "entry", "API_KEY", 0},
		{"project:web", "project", "web", 0},
		{"project:", "project", "", 0},
		{"env:prod", "env", "prod", 0},
		{"env:", "env", "", 0},
		{"vault:", "vault", "", 0},
		{"trust:42", "trust", "", 42},
		{"run:7", "run", "", 7},
		{"passkey:3", "passkey", "", 3},
	} {
		got, err := parseTarget(tc.in)
		if err != nil {
			t.Fatalf("parseTarget(%q): %v", tc.in, err)
		}
		if got.Type != tc.typ || got.Name != tc.name || got.ID != tc.id {
			t.Fatalf("parseTarget(%q) = %+v", tc.in, got)
		}
	}
}

func TestParseTarget_Rejects(t *testing.T) {
	for _, in := range []string{"nonsense:x", "run:", "run:abc", "trust:0", "passkey:-1"} {
		if _, err := parseTarget(in); err == nil {
			t.Fatalf("parseTarget(%q) should have failed", in)
		}
	}
}

// ---- describe ----------------------------------------------------------

func TestRunDescribe_Set(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAnnotationSet, ipc.AnnotationSetResp{ID: 1})

	var rc int
	captureStderr(t, func() {
		rc = runDescribe([]string{"API_KEY", "staging", "Stripe", "key"}, cliScope{})
	})
	if rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	calls := fd.callsFor(ipc.OpAnnotationSet)
	if len(calls) != 1 {
		t.Fatalf("calls = %d", len(calls))
	}
	var req ipc.AnnotationSetReq
	if err := json.Unmarshal(calls[0].Body, &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Words after the target join into one description, so quoting is
	// optional at a shell prompt.
	if req.Text != "staging Stripe key" {
		t.Fatalf("text = %q", req.Text)
	}
	if req.Target.Type != "entry" || req.Target.Name != "API_KEY" {
		t.Fatalf("target = %+v", req.Target)
	}
}

func TestRunDescribe_Show(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAnnotationList, ipc.AnnotationListResp{
		Descriptions: []ipc.AnnotationView{{
			ID: 1, Kind: vault.KindDescription, Body: "staging Stripe key",
			Author: vault.AuthorOwner, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}},
	})
	var rc int
	out := captureStdout(t, func() { rc = runDescribe([]string{"API_KEY"}, cliScope{}) })
	if rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	if strings.TrimSpace(out) != "staging Stripe key" {
		t.Fatalf("stdout = %q", out)
	}
}

// An agent-written description is marked, so a person can see at a glance
// which text they did not write.
func TestRunDescribe_MarksAnAgentAuthor(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAnnotationList, ipc.AnnotationListResp{
		Descriptions: []ipc.AnnotationView{{
			ID: 1, Kind: vault.KindDescription, Body: "placeholder",
			Author: vault.AuthorAgent, AuthorComm: "node",
		}},
	})
	var out string
	stdout := captureStdout(t, func() {
		out = captureStderr(t, func() { runDescribe([]string{"API_KEY"}, cliScope{}) })
	})
	if strings.TrimSpace(stdout) != "placeholder" {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(out, "node") {
		t.Fatalf("stderr = %q, want it to name the agent", out)
	}
}

func TestRunDescribe_Clear(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAnnotationSet, ipc.AnnotationSetResp{ID: 1})
	var rc int
	captureStderr(t, func() { rc = runDescribe([]string{"API_KEY", "--clear"}, cliScope{}) })
	if rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	var req ipc.AnnotationSetReq
	if err := json.Unmarshal(fd.callsFor(ipc.OpAnnotationSet)[0].Body, &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !req.Clear {
		t.Fatal("clear did not reach the daemon")
	}
}

func TestRunDescribe_BadTarget(t *testing.T) {
	startFakeDaemon(t)
	var rc int
	captureStderr(t, func() { rc = runDescribe([]string{"nonsense:x", "text"}, cliScope{}) })
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr", rc)
	}
}

func TestRunDescribe_NoArgs(t *testing.T) {
	startFakeDaemon(t)
	var rc int
	captureStderr(t, func() { rc = runDescribe(nil, cliScope{}) })
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr", rc)
	}
}

// ---- note --------------------------------------------------------------

func TestRunNote_Add(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAnnotationAdd, ipc.AnnotationAddResp{ID: 3})
	var rc int
	captureStderr(t, func() {
		rc = runNote([]string{"add", "API_KEY", "acct", "1234"}, cliScope{})
	})
	if rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	var req ipc.AnnotationAddReq
	if err := json.Unmarshal(fd.callsFor(ipc.OpAnnotationAdd)[0].Body, &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if req.Text != "acct 1234" {
		t.Fatalf("text = %q", req.Text)
	}
}

func TestRunNote_List(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAnnotationList, ipc.AnnotationListResp{
		Notes: []ipc.AnnotationView{{
			ID: 3, Kind: vault.KindNote, Body: "acct 1234",
			Author: vault.AuthorOwner, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}},
		NoteCount: 1,
	})
	var rc int
	out := captureStdout(t, func() { rc = runNote([]string{"ls", "API_KEY"}, cliScope{}) })
	if rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out, "acct 1234") || !strings.Contains(out, "3") {
		t.Fatalf("stdout = %q", out)
	}
}

// Withheld notes are not "no notes", and the CLI must not let the two look
// the same: a person who cannot see their notes needs to be told why.
func TestRunNote_ListWithheld(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAnnotationList, ipc.AnnotationListResp{NoteCount: 2, NotesWithheld: true})
	var rc int
	out := captureStderr(t, func() { rc = runNote([]string{"ls", "API_KEY"}, cliScope{}) })
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr", rc)
	}
	if !strings.Contains(out, "2 note") || !strings.Contains(out, "unlock") {
		t.Fatalf("stderr = %q", out)
	}
}

// Removing a note keeps its text. The CLI has to say so, because a person
// deleting a private note reasonably expects it gone.
func TestRunNote_RemoveSaysItIsATombstone(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAnnotationRemove, ipc.AnnotationRemoveResp{})
	out := captureStderr(t, func() {
		if rc := runNote([]string{"rm", "API_KEY", "3"}, cliScope{}); rc != exitOK {
			t.Errorf("rc = %d", rc)
		}
	})
	if !strings.Contains(out, "history") {
		t.Fatalf("stderr = %q, want it to mention history", out)
	}
}

func TestRunNote_History(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAnnotationHistory, ipc.AnnotationHistoryResp{
		Versions: []ipc.AnnotationVersionView{
			{VersionNo: 1, Op: "create", Body: "first", Author: vault.AuthorAgent, AuthorComm: "node", CreatedAt: time.Now()},
			{VersionNo: 2, Op: "edit", Body: "second", Author: vault.AuthorOwner, CreatedAt: time.Now()},
		},
	})
	var rc int
	out := captureStdout(t, func() { rc = runNote([]string{"history", "API_KEY", "3"}, cliScope{}) })
	if rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	// Both versions, in order, and who wrote each.
	if !strings.Contains(out, "first") || !strings.Contains(out, "second") {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(out, "node") {
		t.Fatalf("stdout = %q, want the agent named", out)
	}
	if strings.Index(out, "first") > strings.Index(out, "second") {
		t.Fatal("history must read oldest first")
	}
}

func TestRunNote_BadSubcommand(t *testing.T) {
	startFakeDaemon(t)
	var rc int
	captureStderr(t, func() { rc = runNote([]string{"frobnicate", "API_KEY"}, cliScope{}) })
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr", rc)
	}
}

func TestRunNote_NoArgs(t *testing.T) {
	startFakeDaemon(t)
	var rc int
	captureStderr(t, func() { rc = runNote(nil, cliScope{}) })
	if rc != exitErr {
		t.Fatalf("rc = %d, want exitErr", rc)
	}
}

func TestRunNote_BadID(t *testing.T) {
	startFakeDaemon(t)
	for _, args := range [][]string{
		{"rm", "API_KEY", "notanumber"},
		{"edit", "API_KEY", "0", "text"},
		{"history", "API_KEY", "-3"},
	} {
		var rc int
		captureStderr(t, func() { rc = runNote(args, cliScope{}) })
		if rc != exitErr {
			t.Fatalf("%v: rc = %d, want exitErr", args, rc)
		}
	}
}

// ---- byn get: the value and the description never share a stream --------

// The contract this feature is most likely to break. A piped or redirected
// get must carry the value and NOTHING else, however much context exists.
func TestRunGet_PipedStdoutCarriesOnlyTheValue(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpGet, ipc.GetResp{
		Name:  "API_KEY",
		Value: []byte("s3cret"),
		Descriptions: []ipc.DescriptionView{
			{Text: "staging Stripe key", Source: "vault", Author: vault.AuthorOwner},
			{Text: "read replica only", Source: ".byn"},
		},
	})
	var rc int
	// captureStdout replaces stdout with a pipe, which is exactly the shape
	// a redirect or a $(…) has.
	out := captureStdout(t, func() {
		rc = runGet([]string{"API_KEY"}, cliScope{})
	})
	if rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	if out != "s3cret" {
		t.Fatalf("stdout = %q, want exactly the value with no description and no newline", out)
	}
}

func TestRunGet_JSONCarriesDescriptions(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpGet, ipc.GetResp{
		Name:  "API_KEY",
		Value: []byte("s3cret"),
		Descriptions: []ipc.DescriptionView{
			{Text: "staging Stripe key", Source: "vault", Author: vault.AuthorAgent, AuthorComm: "node"},
		},
	})
	var rc int
	out := captureStdout(t, func() { rc = runGet([]string{"API_KEY", "--json"}, cliScope{}) })
	if rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	var got struct {
		Name         string                `json:"name"`
		Value        string                `json:"value"`
		Descriptions []ipc.DescriptionView `json:"descriptions"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if got.Value != "s3cret" {
		t.Fatalf("value = %q", got.Value)
	}
	if len(got.Descriptions) != 1 || got.Descriptions[0].Author != vault.AuthorAgent {
		t.Fatalf("descriptions = %+v", got.Descriptions)
	}
}

// --description is the clean extractor: the text alone on stdout, and no
// value fetched at all.
func TestRunGet_DescriptionOnly(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAnnotationList, ipc.AnnotationListResp{
		Descriptions: []ipc.AnnotationView{{
			ID: 1, Kind: vault.KindDescription, Body: "staging Stripe key", Author: vault.AuthorOwner,
		}},
	})
	var rc int
	out := captureStdout(t, func() { rc = runGet([]string{"API_KEY", "--description"}, cliScope{}) })
	if rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	if strings.TrimSpace(out) != "staging Stripe key" {
		t.Fatalf("stdout = %q", out)
	}
	if n := len(fd.callsFor(ipc.OpGet)); n != 0 {
		t.Fatalf("--description read the value (%d get calls)", n)
	}
}

// ---- byn list ----------------------------------------------------------

// The plain listing is an existence probe callers pipe. It must stay
// names-only however much commentary a variable carries.
func TestRunList_PlainListingStaysNamesOnly(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{{
		Name: "API_KEY", Description: "staging Stripe key", Notes: 2,
	}}})
	var rc int
	out := captureStdout(t, func() { rc = runList(nil, cliScope{}) })
	if rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	if strings.TrimSpace(out) != "API_KEY" {
		t.Fatalf("stdout = %q, want the name alone", out)
	}
}

func TestRunList_LongShowsDescriptionAndNoteCount(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{{
		Name: "API_KEY", Description: "staging Stripe key", Notes: 2,
	}}})
	var rc int
	out := captureStdout(t, func() { rc = runList([]string{"--long"}, cliScope{}) })
	if rc != exitOK {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out, "staging Stripe key") {
		t.Fatalf("stdout = %q, want the description", out)
	}
	if !strings.Contains(out, "2 notes") {
		t.Fatalf("stdout = %q, want the note count", out)
	}
	// Never the note text — a listing has no business carrying it, and the
	// response has no field that could.
}

func TestRunList_LongMarksProvenance(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{
		{Name: "AGENT_VAR", Description: "invented", DescriptionAuthor: vault.AuthorAgent, DescriptionComm: "node"},
		{Name: "MANIFEST_VAR", Description: "declared", DescriptionSource: ".byn"},
		{Name: "OWNER_VAR", Description: "mine", DescriptionAuthor: vault.AuthorOwner},
	}})
	out := captureStdout(t, func() { runList([]string{"--long"}, cliScope{}) })
	if !strings.Contains(out, "node") {
		t.Fatalf("stdout = %q, want the agent named", out)
	}
	if !strings.Contains(out, ".byn") {
		t.Fatalf("stdout = %q, want the manifest layer labelled", out)
	}
	// The owner's own words carry no badge — that is the unremarkable case.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "mine") && strings.Contains(line, "[") {
			t.Fatalf("the owner's own description was badged: %q", line)
		}
	}
}
