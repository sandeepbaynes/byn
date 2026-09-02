package ui

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestRouter_HandlesEveryViewItCanProduce is a static guard on the portal's
// single-page router.
//
// It exists because /approvals was unreachable for its whole life. Three pieces
// each looked correct on their own: locationToRoute mapped the path to
// view:"approvals", renderContent knew how to draw that view, and
// renderApprovalsView rendered it properly. Nothing connected the first to the
// third — renderFromLocation had no branch for it — so navigating there fell
// through to the entries case and drew an empty scope. The badge counted two
// waiting requests and the page showed "no env-vars in this scope"; both were
// telling the truth about different things.
//
// No JavaScript test in this repo would have caught it, because every test of a
// view calls its renderer directly. This checks the wiring instead: whatever
// views the route parser can emit, the router must handle.
func TestRouter_HandlesEveryViewItCanProduce(t *testing.T) {
	src := readAsset(t, "assets/app.js")

	produced := viewsIn(t, src, `function locationToRoute\(`, `\bview:\s*"([a-z]+)"`)
	handled := viewsIn(t, src, `async function renderFromLocation\(`, `route\.view === "([a-z]+)"`)

	// entries is the router's fall-through, reached without an explicit branch.
	handled["entries"] = struct{}{}

	var missing []string
	for v := range produced {
		if _, ok := handled[v]; !ok {
			missing = append(missing, v)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("locationToRoute can return these views that renderFromLocation never handles: %v\n"+
			"Each one navigates to a URL that silently renders something else.", missing)
	}
}

// viewsIn collects the capture group of pat within the function that startPat
// begins, stopping at the next top-level function.
func viewsIn(t *testing.T, src, startPat, pat string) map[string]struct{} {
	t.Helper()
	start := regexp.MustCompile(startPat).FindStringIndex(src)
	if start == nil {
		t.Fatalf("could not find %q in app.js — this test is reading the wrong file or the "+
			"function was renamed", startPat)
	}
	body := src[start[1]:]
	if end := regexp.MustCompile(`\n(async )?function `).FindStringIndex(body); end != nil {
		body = body[:end[0]]
	}
	out := map[string]struct{}{}
	for _, m := range regexp.MustCompile(pat).FindAllStringSubmatch(body, -1) {
		out[m[1]] = struct{}{}
	}
	if len(out) == 0 {
		t.Fatalf("found no views via %q — the pattern has drifted from the source", pat)
	}
	return out
}

func readAsset(t *testing.T, name string) string {
	t.Helper()
	b, err := assetsFS.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// The approvals card must carry the request id: it is what you type at a
// terminal, and what an agent printed as approval_id. Without it the browser
// and the terminal are two systems that happen to show similar things.
func TestApprovalCard_ShowsTheRequestID(t *testing.T) {
	src := readAsset(t, "assets/app.js")
	if !strings.Contains(src, `el("span", "approval-id", a.id)`) {
		t.Fatal("the approval card no longer renders the request id")
	}
}
