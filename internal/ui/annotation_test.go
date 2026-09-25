package ui

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// What the portal owes the daemon here is faithful carriage: the rules about
// who may describe or note what live in one place, and the page must not be
// able to mean something different from `byn describe`.
var (
	lastAnnotationList    ipc.AnnotationListReq
	lastAnnotationSet     ipc.AnnotationSetReq
	lastAnnotationAdd     ipc.AnnotationAddReq
	lastAnnotationEdit    ipc.AnnotationEditReq
	lastAnnotationRemove  ipc.AnnotationRemoveReq
	lastAnnotationHistory ipc.AnnotationHistoryReq
)

func portalPost(t *testing.T, path, body string) map[string]any {
	t.Helper()
	ts, c := newTestServer(t, &fakeDisp{})
	defer ts.Close()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:2967")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s returned %d", path, resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func TestPortalAnnotations_Get(t *testing.T) {
	lastAnnotationList = ipc.AnnotationListReq{}
	ts, c := newTestServer(t, &fakeDisp{})
	defer ts.Close()
	resp, err := c.Get(ts.URL + "/api/annotations?type=entry&name=API_KEY&project=web&env=prod")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out ipc.AnnotationListResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Descriptions) != 1 || out.Descriptions[0].Body != "staging Stripe key" {
		t.Fatalf("descriptions = %+v", out.Descriptions)
	}
	if lastAnnotationList.Target.Type != "entry" || lastAnnotationList.Target.Name != "API_KEY" {
		t.Fatalf("target not relayed: %+v", lastAnnotationList.Target)
	}
	if lastAnnotationList.Scope.Project != "web" || lastAnnotationList.Scope.Env != "prod" {
		t.Fatalf("scope not relayed: %+v", lastAnnotationList.Scope)
	}
}

// An id-addressed target (a run, a trust record) reaches the daemon as an id,
// and a malformed one arrives as 0 so the daemon refuses it rather than the
// portal guessing.
func TestPortalAnnotations_IDTargets(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  int64
	}{
		{"type=run&id=42", 42},
		{"type=run&id=notanumber", 0},
		{"type=run&id=-1", 0},
	} {
		lastAnnotationList = ipc.AnnotationListReq{}
		ts, c := newTestServer(t, &fakeDisp{})
		resp, err := c.Get(ts.URL + "/api/annotations?" + tc.query)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		ts.Close()
		if lastAnnotationList.Target.ID != tc.want {
			t.Fatalf("%s: id = %d, want %d", tc.query, lastAnnotationList.Target.ID, tc.want)
		}
	}
}

func TestPortalAnnotations_Describe(t *testing.T) {
	lastAnnotationSet = ipc.AnnotationSetReq{}
	out := portalPost(t, "/api/annotation/describe",
		`{"scope":{"project":"web"},"target":{"type":"entry","name":"API_KEY"},"text":"staging key"}`)
	if out["ok"] != true {
		t.Fatalf("out = %+v", out)
	}
	if lastAnnotationSet.Text != "staging key" {
		t.Fatalf("text = %q", lastAnnotationSet.Text)
	}
	if lastAnnotationSet.Target.Name != "API_KEY" {
		t.Fatalf("target = %+v", lastAnnotationSet.Target)
	}
}

func TestPortalAnnotations_DescribeClear(t *testing.T) {
	lastAnnotationSet = ipc.AnnotationSetReq{}
	portalPost(t, "/api/annotation/describe",
		`{"target":{"type":"entry","name":"API_KEY"},"clear":true}`)
	if !lastAnnotationSet.Clear {
		t.Fatal("clear did not reach the daemon")
	}
}

// One route, three verbs — the portal picks by what the body says, and each
// must reach its own op. Sending an edit as an add would silently create a
// second note instead of changing the one in front of the person.
func TestPortalAnnotations_NoteAddEditRemove(t *testing.T) {
	lastAnnotationAdd = ipc.AnnotationAddReq{}
	out := portalPost(t, "/api/annotation/note",
		`{"target":{"type":"entry","name":"API_KEY"},"text":"acct 1234"}`)
	if out["ok"] != true || lastAnnotationAdd.Text != "acct 1234" {
		t.Fatalf("add: %+v / %+v", out, lastAnnotationAdd)
	}

	lastAnnotationEdit = ipc.AnnotationEditReq{}
	portalPost(t, "/api/annotation/note",
		`{"target":{"type":"entry","name":"API_KEY"},"id":2,"text":"reworded"}`)
	if lastAnnotationEdit.ID != 2 || lastAnnotationEdit.Text != "reworded" {
		t.Fatalf("edit: %+v", lastAnnotationEdit)
	}

	lastAnnotationRemove = ipc.AnnotationRemoveReq{}
	portalPost(t, "/api/annotation/note",
		`{"target":{"type":"entry","name":"API_KEY"},"id":2,"remove":true}`)
	if lastAnnotationRemove.ID != 2 {
		t.Fatalf("remove: %+v", lastAnnotationRemove)
	}
}

func TestPortalAnnotations_History(t *testing.T) {
	lastAnnotationHistory = ipc.AnnotationHistoryReq{}
	ts, c := newTestServer(t, &fakeDisp{})
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/annotation/history",
		strings.NewReader(`{"target":{"type":"entry","name":"API_KEY"},"id":2}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:2967")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out ipc.AnnotationHistoryResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Versions) != 1 || out.Versions[0].AuthorComm != "node" {
		t.Fatalf("versions = %+v", out.Versions)
	}
	if lastAnnotationHistory.ID != 2 {
		t.Fatalf("id = %d", lastAnnotationHistory.ID)
	}
}

// Every write route is POST-only and same-origin, like the rest of the data
// plane: a cross-origin page must not be able to reword what an agent reads.
func TestPortalAnnotations_WritesRefuseGET(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	defer ts.Close()
	for _, p := range []string{"/api/annotation/describe", "/api/annotation/note", "/api/annotation/history"} {
		resp, err := c.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s GET = %d, want 405", p, resp.StatusCode)
		}
	}
}
