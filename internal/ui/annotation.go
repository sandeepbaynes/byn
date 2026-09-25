package ui

import (
	"net/http"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// Annotations in the portal.
//
// The daemon decides who may read or write what; these handlers only carry the
// request. In particular the notes half of a listing comes back empty with
// notes_withheld set when the caller has no credential, and the page renders
// that as "there is something here" rather than as "there is nothing" — the
// difference matters and the portal must not flatten it.

type annotationTargetBody struct {
	Type string `json:"type"`
	Name string `json:"name"`
	ID   int64  `json:"id"`
}

func (b annotationTargetBody) toIPC() ipc.AnnotationTarget {
	return ipc.AnnotationTarget{Type: b.Type, Name: b.Name, ID: b.ID}
}

// GET /api/annotations?type=&name=&id=&kind=&vault=&project=&env=
//
// Reads are a GET because they change nothing. Descriptions come back for any
// caller; notes need the session the daemon checks.
func (s *Server) handleAnnotationsGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := ipc.AnnotationTarget{Type: q.Get("type"), Name: q.Get("name")}
	if id := q.Get("id"); id != "" {
		target.ID = parseInt64(id)
	}
	req := ipc.AnnotationListReq{
		Scope:  scopeFromQuery(r),
		Target: target,
		Kind:   q.Get("kind"),
	}
	var resp ipc.AnnotationListResp
	if !s.run(w, r, ipc.OpAnnotationList, req, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/annotation/describe {scope, target, text, clear, password?, presence_token?}
func (s *Server) handleAnnotationDescribe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope         scopeBody            `json:"scope"`
		Target        annotationTargetBody `json:"target"`
		Text          string               `json:"text"`
		Clear         bool                 `json:"clear"`
		Password      string               `json:"password"`
		PresenceToken []byte               `json:"presence_token"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.AnnotationSetReq{
		Scope: body.Scope.toIPC(), Target: body.Target.toIPC(),
		Text: body.Text, Clear: body.Clear,
		Password: []byte(body.Password), PresenceToken: body.PresenceToken,
	}
	var resp ipc.AnnotationSetResp
	if !s.runInVault(w, r, body.Scope.Vault, ipc.OpAnnotationSet, req, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": resp.ID})
}

// POST /api/annotation/note {scope, target, text, id?, remove?, password?, presence_token?}
//
// One route for add / edit / remove because they are one affordance in the
// page: a note box with an edit and a delete on each row.
func (s *Server) handleAnnotationNote(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope         scopeBody            `json:"scope"`
		Target        annotationTargetBody `json:"target"`
		Text          string               `json:"text"`
		ID            int64                `json:"id"`
		Remove        bool                 `json:"remove"`
		Password      string               `json:"password"`
		PresenceToken []byte               `json:"presence_token"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	scope, target := body.Scope.toIPC(), body.Target.toIPC()
	pw, tok := []byte(body.Password), body.PresenceToken

	switch {
	case body.Remove:
		req := ipc.AnnotationRemoveReq{Scope: scope, Target: target, ID: body.ID, Password: pw, PresenceToken: tok}
		if !s.runInVault(w, r, body.Scope.Vault, ipc.OpAnnotationRemove, req, &ipc.AnnotationRemoveResp{}) {
			return
		}
	case body.ID > 0:
		req := ipc.AnnotationEditReq{Scope: scope, Target: target, ID: body.ID, Text: body.Text, Password: pw, PresenceToken: tok}
		if !s.runInVault(w, r, body.Scope.Vault, ipc.OpAnnotationEdit, req, &ipc.AnnotationEditResp{}) {
			return
		}
	default:
		req := ipc.AnnotationAddReq{Scope: scope, Target: target, Text: body.Text, Password: pw, PresenceToken: tok}
		var resp ipc.AnnotationAddResp
		if !s.runInVault(w, r, body.Scope.Vault, ipc.OpAnnotationAdd, req, &resp) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": resp.ID})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /api/annotation/history {scope, target, id, password?, presence_token?}
func (s *Server) handleAnnotationHistory(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope         scopeBody            `json:"scope"`
		Target        annotationTargetBody `json:"target"`
		ID            int64                `json:"id"`
		Password      string               `json:"password"`
		PresenceToken []byte               `json:"presence_token"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.AnnotationHistoryReq{
		Scope: body.Scope.toIPC(), Target: body.Target.toIPC(), ID: body.ID,
		Password: []byte(body.Password), PresenceToken: body.PresenceToken,
	}
	var resp ipc.AnnotationHistoryResp
	if !s.runInVault(w, r, body.Scope.Vault, ipc.OpAnnotationHistory, req, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// parseInt64 is a forgiving id parser: anything unparseable becomes 0, which
// the daemon refuses as "that type needs an id". A malformed query string
// should produce that error, not a 500.
func parseInt64(s string) int64 {
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int64(r-'0')
		if n > 1<<62 {
			return 0
		}
	}
	return n
}
