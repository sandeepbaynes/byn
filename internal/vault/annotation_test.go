package vault

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// entryRefFor resolves the object reference for one env var in scope, the way
// the daemon does before annotating it.
func entryRefFor(t *testing.T, st *Store, scope Scope, name string) ObjectRef {
	t.Helper()
	ctx := context.Background()
	projectID, envID, err := st.scopeIDs(ctx, scope)
	if err != nil {
		t.Fatalf("scopeIDs: %v", err)
	}
	var id int64
	if err := st.db.QueryRowContext(ctx,
		`SELECT id FROM entries WHERE project_id = ? AND env_id = ? AND name = ?`,
		projectID, envID, name).Scan(&id); err != nil {
		t.Fatalf("entry id for %s: %v", name, err)
	}
	return EntryObject(id, projectID, envID)
}

func putVar(t *testing.T, st *Store, name, value string) ObjectRef {
	t.Helper()
	if err := st.PutEnvVar(context.Background(), defaultScope(), name, []byte(value), PutOpt{}); err != nil {
		t.Fatalf("PutEnvVar %s: %v", name, err)
	}
	return entryRefFor(t, st, defaultScope(), name)
}

// ---- descriptions -------------------------------------------------------

func TestSetDescription_RoundTrip(t *testing.T) {
	st, _ := newOpenedVault(t)
	ref := putVar(t, st, "API_KEY", "v")
	ctx := context.Background()

	if err := st.SetDescription(ctx, ref, "staging Stripe key", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}
	got, err := st.GetDescription(ctx, ref)
	if err != nil {
		t.Fatalf("GetDescription: %v", err)
	}
	if got.Body != "staging Stripe key" {
		t.Fatalf("body = %q", got.Body)
	}
	if got.Author != AuthorOwner {
		t.Fatalf("author = %q, want owner", got.Author)
	}
}

// A description is the field a caller without a credential is meant to read,
// so a locked vault must still serve it — and still accept a change to it,
// since rewording a sentence has no business exposing every secret in the
// vault. This is the behaviour the owner asked for explicitly.
func TestDescription_WorksWhileLocked(t *testing.T) {
	st, _ := newOpenedVault(t)
	ref := putVar(t, st, "API_KEY", "v")
	ctx := context.Background()
	if err := st.SetDescription(ctx, ref, "first", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}

	st.Lock()

	got, err := st.GetDescription(ctx, ref)
	if err != nil {
		t.Fatalf("GetDescription while locked: %v", err)
	}
	if got.Body != "first" {
		t.Fatalf("body = %q", got.Body)
	}
	if err := st.SetDescription(ctx, ref, "second", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription while locked: %v", err)
	}
	if got, err = st.GetDescription(ctx, ref); err != nil || got.Body != "second" {
		t.Fatalf("after rewrite: %q, %v", got.Body, err)
	}
}

func TestSetDescription_ReplacesAndKeepsHistory(t *testing.T) {
	st, _ := newOpenedVault(t)
	ref := putVar(t, st, "API_KEY", "v")
	ctx := context.Background()

	if err := st.SetDescription(ctx, ref, "written by the agent", AgentAuthor("node")); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}
	if err := st.SetDescription(ctx, ref, "corrected by the owner", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}

	cur, err := st.GetDescription(ctx, ref)
	if err != nil {
		t.Fatalf("GetDescription: %v", err)
	}
	if cur.Body != "corrected by the owner" || cur.Author != AuthorOwner {
		t.Fatalf("current = %q by %q", cur.Body, cur.Author)
	}

	hist, err := st.AnnotationHistory(ctx, ref, cur.ID)
	if err != nil {
		t.Fatalf("AnnotationHistory: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("history len = %d, want 2", len(hist))
	}
	if hist[0].Body != "written by the agent" || hist[0].Author != AuthorAgent || hist[0].AuthorComm != "node" {
		t.Fatalf("v1 = %+v", hist[0])
	}
	if hist[0].Op != "create" || hist[1].Op != "edit" {
		t.Fatalf("ops = %q, %q", hist[0].Op, hist[1].Op)
	}
}

func TestSetDescription_TooLarge(t *testing.T) {
	st, _ := newOpenedVault(t)
	ref := putVar(t, st, "API_KEY", "v")
	err := st.SetDescription(context.Background(), ref, strings.Repeat("x", MaxDescriptionLen+1), OwnerAuthor())
	if err == nil {
		t.Fatal("want error for an oversized description")
	}
}

func TestSetDescription_RejectsEmptyAndBadRef(t *testing.T) {
	st, _ := newOpenedVault(t)
	ref := putVar(t, st, "API_KEY", "v")
	ctx := context.Background()

	if err := st.SetDescription(ctx, ref, "   ", OwnerAuthor()); err == nil {
		t.Fatal("want error for blank text")
	}
	if err := st.SetDescription(ctx, ObjectRef{Type: "nonsense", ID: "1"}, "x", OwnerAuthor()); !errors.Is(err, ErrNotAnnotatable) {
		t.Fatalf("unknown type: %v, want ErrNotAnnotatable", err)
	}
	if err := st.SetDescription(ctx, ObjectRef{Type: ObjectEntry}, "x", OwnerAuthor()); !errors.Is(err, ErrNotAnnotatable) {
		t.Fatalf("empty id: %v, want ErrNotAnnotatable", err)
	}
	if err := st.SetDescription(ctx, ref, "x", Author{Kind: "someone-else"}); err == nil {
		t.Fatal("want error for an unknown author")
	}
}

func TestGetDescription_NotFound(t *testing.T) {
	st, _ := newOpenedVault(t)
	ref := putVar(t, st, "API_KEY", "v")
	if _, err := st.GetDescription(context.Background(), ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestDescriptions_Batch(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	a := putVar(t, st, "A", "1")
	b := putVar(t, st, "B", "2")
	putVar(t, st, "C", "3")

	if err := st.SetDescription(ctx, a, "first", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}
	if err := st.SetDescription(ctx, b, "second", AgentAuthor("node")); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}

	got, err := st.Descriptions(ctx, ObjectEntry, []string{a.ID, b.ID, "999999"})
	if err != nil {
		t.Fatalf("Descriptions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[a.ID].Body != "first" || got[b.ID].Body != "second" {
		t.Fatalf("got %+v", got)
	}
	if got[b.ID].Author != AuthorAgent || got[b.ID].AuthorComm != "node" {
		t.Fatalf("provenance lost: %+v", got[b.ID])
	}

	empty, err := st.Descriptions(ctx, ObjectEntry, nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty batch: %v, %v", empty, err)
	}
}

// ---- notes --------------------------------------------------------------

func TestAddNote_RoundTripAndOrdering(t *testing.T) {
	st, _ := newOpenedVault(t)
	ref := putVar(t, st, "API_KEY", "v")
	ctx := context.Background()

	if _, err := st.AddNote(ctx, ref, "older", OwnerAuthor()); err != nil {
		t.Fatalf("AddNote: %v", err)
	}
	if _, err := st.AddNote(ctx, ref, "newer", OwnerAuthor()); err != nil {
		t.Fatalf("AddNote: %v", err)
	}

	notes, err := st.ListNotes(ctx, ref)
	if err != nil {
		t.Fatalf("ListNotes: %v", err)
	}
	if len(notes) != 2 {
		t.Fatalf("len = %d, want 2", len(notes))
	}
	if notes[0].Body != "newer" || notes[1].Body != "older" {
		t.Fatalf("order = %q, %q; want newest first", notes[0].Body, notes[1].Body)
	}
}

// The point of the split: a note must NOT be readable without the key, while
// the fact that one exists stays visible so a locked listing can say so.
func TestNotes_LockedVaultHidesTextButNotCount(t *testing.T) {
	st, _ := newOpenedVault(t)
	ref := putVar(t, st, "API_KEY", "v")
	ctx := context.Background()
	if _, err := st.AddNote(ctx, ref, "acct 1234, ask billing first", OwnerAuthor()); err != nil {
		t.Fatalf("AddNote: %v", err)
	}

	st.Lock()

	if _, err := st.ListNotes(ctx, ref); !errors.Is(err, ErrLocked) {
		t.Fatalf("ListNotes while locked: %v, want ErrLocked", err)
	}
	if _, err := st.AddNote(ctx, ref, "x", OwnerAuthor()); !errors.Is(err, ErrLocked) {
		t.Fatalf("AddNote while locked: %v, want ErrLocked", err)
	}
	n, err := st.NoteCount(ctx, ref)
	if err != nil {
		t.Fatalf("NoteCount while locked: %v", err)
	}
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
}

// A locked vault is not a wall when the caller can prove who they are.
func TestNotes_WithPassword(t *testing.T) {
	st, _ := newOpenedVault(t)
	ref := putVar(t, st, "API_KEY", "v")
	ctx := context.Background()
	st.Lock()

	pw := []byte(testPassword)
	id, err := st.AddNoteWithPassword(ctx, pw, ref, "written while locked", OwnerAuthor())
	if err != nil {
		t.Fatalf("AddNoteWithPassword: %v", err)
	}
	notes, err := st.ListNotesWithPassword(ctx, pw, ref)
	if err != nil {
		t.Fatalf("ListNotesWithPassword: %v", err)
	}
	if len(notes) != 1 || notes[0].Body != "written while locked" {
		t.Fatalf("got %+v", notes)
	}
	if err := st.EditNoteWithPassword(ctx, pw, ref, id, "reworded while locked", OwnerAuthor()); err != nil {
		t.Fatalf("EditNoteWithPassword: %v", err)
	}
	if _, err := st.AddNoteWithPassword(ctx, []byte("wrong"), ref, "x", OwnerAuthor()); err == nil {
		t.Fatal("want error for a wrong password")
	}
}

// The AAD binds a note to its object, its kind and its own uid. Moving a
// ciphertext anywhere else must fail to open rather than decrypt into the
// wrong place.
func TestNote_CiphertextCannotMoveBetweenObjects(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	a := putVar(t, st, "A", "1")
	b := putVar(t, st, "B", "2")

	if _, err := st.AddNote(ctx, a, "belongs to A", OwnerAuthor()); err != nil {
		t.Fatalf("AddNote: %v", err)
	}
	if _, err := st.AddNote(ctx, b, "belongs to B", OwnerAuthor()); err != nil {
		t.Fatalf("AddNote: %v", err)
	}

	// Repoint A's row at B, exactly as an attacker with write access to the
	// database would.
	if _, err := st.db.ExecContext(ctx,
		`UPDATE annotations SET object_id = ? WHERE object_id = ? AND kind = 'note'`,
		b.ID, a.ID); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := st.ListNotes(ctx, b); err == nil {
		t.Fatal("a note moved to another object must not decrypt")
	}
}

// Two notes on the SAME object must not share a key either, which is what the
// per-annotation uid is for.
func TestNote_CiphertextCannotMoveBetweenNotesOnOneObject(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	ref := putVar(t, st, "API_KEY", "v")

	first, err := st.AddNote(ctx, ref, "first", OwnerAuthor())
	if err != nil {
		t.Fatalf("AddNote: %v", err)
	}
	second, err := st.AddNote(ctx, ref, "second", OwnerAuthor())
	if err != nil {
		t.Fatalf("AddNote: %v", err)
	}

	var ct []byte
	if err := st.db.QueryRowContext(ctx, `SELECT body_enc FROM annotations WHERE id = ?`, first).Scan(&ct); err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE annotations SET body_enc = ? WHERE id = ?`, ct, second); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := st.ListNotes(ctx, ref); err == nil {
		t.Fatal("a note's ciphertext must not open under another note's key")
	}
}

// A note on an entry derives from that entry's scope key; a note on anything
// else derives from the vault key. Both must round-trip, and the scoped one
// must record which lineage it used.
func TestNote_KeyDomains(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()

	entry := putVar(t, st, "API_KEY", "v")
	if _, err := st.AddNote(ctx, entry, "scoped", OwnerAuthor()); err != nil {
		t.Fatalf("AddNote entry: %v", err)
	}

	projectID, _, err := st.scopeIDs(ctx, defaultScope())
	if err != nil {
		t.Fatalf("scopeIDs: %v", err)
	}
	project := Ref(ObjectProject, projectID)
	if _, err := st.AddNote(ctx, project, "unscoped", OwnerAuthor()); err != nil {
		t.Fatalf("AddNote project: %v", err)
	}

	for _, tc := range []struct {
		ref  ObjectRef
		want string
		dom  string
	}{
		{entry, "scoped", keyDomainEnv},
		{project, "unscoped", keyDomainVault},
	} {
		notes, err := st.ListNotes(ctx, tc.ref)
		if err != nil {
			t.Fatalf("ListNotes %s: %v", tc.ref.Type, err)
		}
		if len(notes) != 1 || notes[0].Body != tc.want {
			t.Fatalf("%s: got %+v", tc.ref.Type, notes)
		}
		var domain string
		if err := st.db.QueryRowContext(ctx,
			`SELECT key_domain FROM annotations WHERE id = ?`, notes[0].ID).Scan(&domain); err != nil {
			t.Fatalf("key_domain: %v", err)
		}
		if domain != tc.dom {
			t.Fatalf("%s: key_domain = %q, want %q", tc.ref.Type, domain, tc.dom)
		}
	}
}

// An unattended caller annotating what it just created, on a LOCKED vault:
// the note seals under the scope's authored key and the same caller reads it
// back without the master password — the same trade PutEnvVarAuthored makes.
func TestNote_AuthoredKeyWorksWhileLocked(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()

	authored, err := st.CaptureAuthoredKey(ctx, defaultScope())
	if err != nil {
		t.Fatalf("CaptureAuthoredKey: %v", err)
	}
	ref := putVar(t, st, "AGENT_TOKEN", "v")
	st.Lock()

	if _, err := st.AddNoteAuthored(ctx, ref, "placeholder, needs a real value", authored, AgentAuthor("node")); err != nil {
		t.Fatalf("AddNoteAuthored: %v", err)
	}
	notes, err := st.ListNotesAuthored(ctx, ref, authored)
	if err != nil {
		t.Fatalf("ListNotesAuthored: %v", err)
	}
	if len(notes) != 1 || notes[0].Body != "placeholder, needs a real value" {
		t.Fatalf("got %+v", notes)
	}
	if notes[0].Author != AuthorAgent || notes[0].AuthorComm != "node" {
		t.Fatalf("provenance = %q/%q", notes[0].Author, notes[0].AuthorComm)
	}

	if _, err := st.AddNoteAuthored(ctx, ref, "x", nil, AgentAuthor("node")); !errors.Is(err, ErrLocked) {
		t.Fatalf("no key: %v, want ErrLocked", err)
	}
	if _, err := st.AddNoteAuthored(ctx, Ref(ObjectProject, 1), "x", authored, AgentAuthor("node")); !errors.Is(err, ErrNotAnnotatable) {
		t.Fatalf("non-entry: %v, want ErrNotAnnotatable", err)
	}
}

// The owner unlocking later can read what the agent wrote, through the same
// vault key the authored key descends from.
func TestNote_AuthoredNoteVisibleToOwner(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	authored, err := st.CaptureAuthoredKey(ctx, defaultScope())
	if err != nil {
		t.Fatalf("CaptureAuthoredKey: %v", err)
	}
	ref := putVar(t, st, "AGENT_TOKEN", "v")
	if _, err := st.AddNoteAuthored(ctx, ref, "from the agent", authored, AgentAuthor("node")); err != nil {
		t.Fatalf("AddNoteAuthored: %v", err)
	}

	// The owner's read path needs the authored key too — it is not derivable
	// from the vault key at this layer, so ListNotes must say so rather than
	// silently return nothing or report corruption.
	if _, err := st.ListNotes(ctx, ref); !errors.Is(err, errAuthoredKeyUnsupported) {
		t.Fatalf("ListNotes over an authored note: %v", err)
	}
	if n, err := st.NoteCount(ctx, ref); err != nil || n != 1 {
		t.Fatalf("NoteCount = %d, %v", n, err)
	}
}

func TestEditNote_KeepsHistory(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	ref := putVar(t, st, "API_KEY", "v")

	id, err := st.AddNote(ctx, ref, "original", OwnerAuthor())
	if err != nil {
		t.Fatalf("AddNote: %v", err)
	}
	if err := st.EditNote(ctx, ref, id, "revised", OwnerAuthor()); err != nil {
		t.Fatalf("EditNote: %v", err)
	}

	notes, err := st.ListNotes(ctx, ref)
	if err != nil {
		t.Fatalf("ListNotes: %v", err)
	}
	if len(notes) != 1 || notes[0].Body != "revised" {
		t.Fatalf("got %+v", notes)
	}
	hist, err := st.AnnotationHistory(ctx, ref, id)
	if err != nil {
		t.Fatalf("AnnotationHistory: %v", err)
	}
	if len(hist) != 2 || hist[0].Body != "original" || hist[1].Body != "revised" {
		t.Fatalf("history = %+v", hist)
	}
}

func TestEditNote_Missing(t *testing.T) {
	st, _ := newOpenedVault(t)
	ref := putVar(t, st, "API_KEY", "v")
	if err := st.EditNote(context.Background(), ref, 4242, "x", OwnerAuthor()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestNote_TooLargeOrEmpty(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	ref := putVar(t, st, "API_KEY", "v")

	if _, err := st.AddNote(ctx, ref, strings.Repeat("x", MaxNoteLen+1), OwnerAuthor()); err == nil {
		t.Fatal("want error for an oversized note")
	}
	if _, err := st.AddNote(ctx, ref, "\t\n ", OwnerAuthor()); err == nil {
		t.Fatal("want error for a blank note")
	}
}

func TestAddNote_CapPerObject(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	ref := putVar(t, st, "API_KEY", "v")

	for i := 0; i < MaxNotesPerObject; i++ {
		if _, err := st.AddNote(ctx, ref, "n"+strconv.Itoa(i), OwnerAuthor()); err != nil {
			t.Fatalf("AddNote %d: %v", i, err)
		}
	}
	if _, err := st.AddNote(ctx, ref, "one too many", OwnerAuthor()); !errors.Is(err, ErrTooManyNotes) {
		t.Fatalf("err = %v, want ErrTooManyNotes", err)
	}
}

// ---- removal: a tombstone, not an erasure -------------------------------

func TestRemoveAnnotation_IsATombstone(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	ref := putVar(t, st, "API_KEY", "v")

	id, err := st.AddNote(ctx, ref, "the text", OwnerAuthor())
	if err != nil {
		t.Fatalf("AddNote: %v", err)
	}
	if err := st.RemoveAnnotation(ctx, ref, id, OwnerAuthor()); err != nil {
		t.Fatalf("RemoveAnnotation: %v", err)
	}

	notes, err := st.ListNotes(ctx, ref)
	if err != nil {
		t.Fatalf("ListNotes: %v", err)
	}
	if len(notes) != 0 {
		t.Fatalf("removed note still listed: %+v", notes)
	}

	hist, err := st.AnnotationHistory(ctx, ref, id)
	if err != nil {
		t.Fatalf("AnnotationHistory: %v", err)
	}
	if len(hist) != 2 || hist[0].Body != "the text" || hist[1].Op != "delete" {
		t.Fatalf("history = %+v", hist)
	}

	if err := st.RemoveAnnotation(ctx, ref, id, OwnerAuthor()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second remove: %v, want ErrNotFound", err)
	}
}

// Removing a description frees the slot: the partial unique index must not
// count a tombstone.
func TestRemoveDescription_AllowsANewOne(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	ref := putVar(t, st, "API_KEY", "v")

	if err := st.SetDescription(ctx, ref, "first", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}
	cur, err := st.GetDescription(ctx, ref)
	if err != nil {
		t.Fatalf("GetDescription: %v", err)
	}
	if err := st.RemoveAnnotation(ctx, ref, cur.ID, OwnerAuthor()); err != nil {
		t.Fatalf("RemoveAnnotation: %v", err)
	}
	if _, err := st.GetDescription(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after remove: %v, want ErrNotFound", err)
	}
	if err := st.SetDescription(ctx, ref, "second", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription after remove: %v", err)
	}
	got, err := st.GetDescription(ctx, ref)
	if err != nil || got.Body != "second" {
		t.Fatalf("got %q, %v", got.Body, err)
	}
}

// ---- cascade ------------------------------------------------------------

func annotationCount(t *testing.T, st *Store) int {
	t.Helper()
	var n int
	if err := st.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM annotations`).Scan(&n); err != nil {
		t.Fatalf("count annotations: %v", err)
	}
	return n
}

func versionCount(t *testing.T, st *Store) int {
	t.Helper()
	var n int
	if err := st.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM annotation_versions`).Scan(&n); err != nil {
		t.Fatalf("count versions: %v", err)
	}
	return n
}

func TestDeleteEnvVar_TakesItsAnnotations(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	ref := putVar(t, st, "API_KEY", "v")
	if err := st.SetDescription(ctx, ref, "d", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}
	if _, err := st.AddNote(ctx, ref, "n", OwnerAuthor()); err != nil {
		t.Fatalf("AddNote: %v", err)
	}

	if err := st.DeleteEnvVar(ctx, defaultScope(), "API_KEY"); err != nil {
		t.Fatalf("DeleteEnvVar: %v", err)
	}
	if n := annotationCount(t, st); n != 0 {
		t.Fatalf("%d annotations survived the entry", n)
	}
	// History goes with them — the object it described is gone.
	if n := versionCount(t, st); n != 0 {
		t.Fatalf("%d versions survived the entry", n)
	}
}

func TestClearEnvVars_TakesItsAnnotations(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	for _, n := range []string{"A", "B"} {
		ref := putVar(t, st, n, "v")
		if err := st.SetDescription(ctx, ref, "d", OwnerAuthor()); err != nil {
			t.Fatalf("SetDescription: %v", err)
		}
	}
	if _, err := st.ClearEnvVars(ctx, defaultScope()); err != nil {
		t.Fatalf("ClearEnvVars: %v", err)
	}
	if n := annotationCount(t, st); n != 0 {
		t.Fatalf("%d annotations survived the clear", n)
	}
}

// The fan-out case: deleting a project takes its envs and its entries through
// the foreign keys, and every annotation on all three levels must go too.
func TestDeleteProject_TakesTheWholeTreesAnnotations(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()

	if err := st.CreateProject(ctx, "web"); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if err := st.CreateEnv(ctx, "web", "prod"); err != nil {
		t.Fatalf("CreateEnv: %v", err)
	}
	scope := Scope{Project: "web", Env: "prod"}
	if err := st.PutEnvVar(ctx, scope, "API_KEY", []byte("v"), PutOpt{}); err != nil {
		t.Fatalf("PutEnvVar: %v", err)
	}

	projectID, envID, err := st.scopeIDs(ctx, scope)
	if err != nil {
		t.Fatalf("scopeIDs: %v", err)
	}
	entry := entryRefFor(t, st, scope, "API_KEY")
	for _, ref := range []ObjectRef{Ref(ObjectProject, projectID), Ref(ObjectEnv, envID), entry} {
		if err := st.SetDescription(ctx, ref, "d", OwnerAuthor()); err != nil {
			t.Fatalf("SetDescription %s: %v", ref.Type, err)
		}
	}
	if annotationCount(t, st) != 3 {
		t.Fatalf("setup: %d annotations", annotationCount(t, st))
	}

	if err := st.DeleteProject(ctx, "web"); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}
	if n := annotationCount(t, st); n != 0 {
		t.Fatalf("%d annotations survived the project", n)
	}
}

func TestDeleteEnv_TakesItsAnnotations(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.CreateEnv(ctx, DefaultProjectName, "prod"); err != nil {
		t.Fatalf("CreateEnv: %v", err)
	}
	scope := Scope{Project: DefaultProjectName, Env: "prod"}
	if err := st.PutEnvVar(ctx, scope, "API_KEY", []byte("v"), PutOpt{}); err != nil {
		t.Fatalf("PutEnvVar: %v", err)
	}
	_, envID, err := st.scopeIDs(ctx, scope)
	if err != nil {
		t.Fatalf("scopeIDs: %v", err)
	}
	if err := st.SetDescription(ctx, Ref(ObjectEnv, envID), "d", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}
	if err := st.SetDescription(ctx, entryRefFor(t, st, scope, "API_KEY"), "d", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}

	if err := st.DeleteEnv(ctx, DefaultProjectName, "prod"); err != nil {
		t.Fatalf("DeleteEnv: %v", err)
	}
	if n := annotationCount(t, st); n != 0 {
		t.Fatalf("%d annotations survived the env", n)
	}
}

func TestDeleteAnnotationsFor_Explicit(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()

	// A trust record lives outside this database, so its annotations are
	// reached by id rather than by the orphan sweep.
	ref := Ref(ObjectTrust, 7)
	if err := st.SetDescription(ctx, ref, "the nightly agent's scope", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}
	if err := st.DeleteAnnotationsFor(ctx, ObjectTrust); err != nil {
		t.Fatalf("DeleteAnnotationsFor with no ids: %v", err)
	}
	if n := annotationCount(t, st); n != 1 {
		t.Fatalf("empty id list deleted something: %d", n)
	}
	if err := st.DeleteAnnotationsFor(ctx, ObjectTrust, ref.ID); err != nil {
		t.Fatalf("DeleteAnnotationsFor: %v", err)
	}
	if n := annotationCount(t, st); n != 0 {
		t.Fatalf("%d annotations survived", n)
	}
}

// An annotation on a trust record is NOT an orphan: that table is not in this
// database, so the sweep must leave it alone rather than delete what it cannot
// see.
func TestOrphanSweep_LeavesOffDatabaseObjectsAlone(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.SetDescription(ctx, Ref(ObjectTrust, 7), "d", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}
	if err := st.SetDescription(ctx, ObjectRef{Type: ObjectVault, ID: "v1"}, "d", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}

	n, err := st.OrphanAnnotations(ctx)
	if err != nil {
		t.Fatalf("OrphanAnnotations: %v", err)
	}
	if n != 0 {
		t.Fatalf("orphans = %d, want 0", n)
	}
	swept, err := st.SweepOrphanAnnotations(ctx)
	if err != nil {
		t.Fatalf("SweepOrphanAnnotations: %v", err)
	}
	if swept != 0 || annotationCount(t, st) != 2 {
		t.Fatalf("swept %d, left %d", swept, annotationCount(t, st))
	}
}

// The backstop for a delete path that forgets: an annotation whose row went
// away out of band is reported, then swept.
func TestOrphanSweep_FindsAndRemoves(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	ref := putVar(t, st, "API_KEY", "v")
	if err := st.SetDescription(ctx, ref, "d", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `DELETE FROM entries WHERE id = ?`, ref.ID); err != nil {
		t.Fatalf("out-of-band delete: %v", err)
	}

	n, err := st.OrphanAnnotations(ctx)
	if err != nil {
		t.Fatalf("OrphanAnnotations: %v", err)
	}
	if n != 1 {
		t.Fatalf("orphans = %d, want 1", n)
	}
	swept, err := st.SweepOrphanAnnotations(ctx)
	if err != nil {
		t.Fatalf("SweepOrphanAnnotations: %v", err)
	}
	if swept != 1 || annotationCount(t, st) != 0 {
		t.Fatalf("swept %d, left %d", swept, annotationCount(t, st))
	}
}

// ---- history ------------------------------------------------------------

func TestAnnotationHistory_NoteNeedsTheKey(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	ref := putVar(t, st, "API_KEY", "v")
	id, err := st.AddNote(ctx, ref, "private", OwnerAuthor())
	if err != nil {
		t.Fatalf("AddNote: %v", err)
	}
	st.Lock()
	if _, err := st.AnnotationHistory(ctx, ref, id); !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked", err)
	}
}

// A description's history needs no key, because the description never did.
func TestAnnotationHistory_DescriptionWorksLocked(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	ref := putVar(t, st, "API_KEY", "v")
	if err := st.SetDescription(ctx, ref, "d", AgentAuthor("node")); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}
	cur, err := st.GetDescription(ctx, ref)
	if err != nil {
		t.Fatalf("GetDescription: %v", err)
	}
	st.Lock()
	hist, err := st.AnnotationHistory(ctx, ref, cur.ID)
	if err != nil {
		t.Fatalf("AnnotationHistory while locked: %v", err)
	}
	if len(hist) != 1 || hist[0].Body != "d" || hist[0].AuthorComm != "node" {
		t.Fatalf("history = %+v", hist)
	}
}

func TestAnnotationHistory_Missing(t *testing.T) {
	st, _ := newOpenedVault(t)
	ref := putVar(t, st, "API_KEY", "v")
	if _, err := st.AnnotationHistory(context.Background(), ref, 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// ---- resolving objects --------------------------------------------------

func TestEntryObjectRef_FollowsInheritance(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.CreateEnv(ctx, DefaultProjectName, "prod"); err != nil {
		t.Fatalf("CreateEnv: %v", err)
	}
	// Only the default env has the value; prod inherits it.
	putVar(t, st, "SHARED", "v")
	prod := Scope{Project: DefaultProjectName, Env: "prod"}

	fromDefault := entryRefFor(t, st, defaultScope(), "SHARED")
	got, err := st.EntryObjectRef(ctx, prod, "SHARED")
	if err != nil {
		t.Fatalf("EntryObjectRef: %v", err)
	}
	if got.ID != fromDefault.ID {
		t.Fatalf("inherited name resolved to %s, want the default env's row %s", got.ID, fromDefault.ID)
	}

	// An override gets its own object.
	if err := st.PutEnvVar(ctx, prod, "SHARED", []byte("own"), PutOpt{}); err != nil {
		t.Fatalf("PutEnvVar: %v", err)
	}
	got, err = st.EntryObjectRef(ctx, prod, "SHARED")
	if err != nil {
		t.Fatalf("EntryObjectRef: %v", err)
	}
	if got.ID == fromDefault.ID {
		t.Fatal("an override must annotate its own row, not default's")
	}
}

func TestEntryObjectRef_Missing(t *testing.T) {
	st, _ := newOpenedVault(t)
	if _, err := st.EntryObjectRef(context.Background(), defaultScope(), "NOPE"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestProjectEnvVaultObjectRefs(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()

	pref, err := st.ProjectObjectRef(ctx, DefaultProjectName)
	if err != nil || pref.Type != ObjectProject || pref.ID == "" {
		t.Fatalf("ProjectObjectRef: %+v, %v", pref, err)
	}
	eref, err := st.EnvObjectRef(ctx, DefaultProjectName, DefaultEnvName)
	if err != nil || eref.Type != ObjectEnv || eref.ID == "" {
		t.Fatalf("EnvObjectRef: %+v, %v", eref, err)
	}
	vref := st.VaultObjectRef()
	if vref.Type != ObjectVault || vref.ID != st.VaultID() {
		t.Fatalf("VaultObjectRef = %+v", vref)
	}
	if _, err := st.ProjectObjectRef(ctx, "no-such-project"); err == nil {
		t.Fatal("want error for an unknown project")
	}
	if _, err := st.EnvObjectRef(ctx, DefaultProjectName, "no-such-env"); err == nil {
		t.Fatal("want error for an unknown env")
	}
}

// ---- listing enrichment -------------------------------------------------

func TestEntryAnnotations_DescriptionsAndCounts(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	a := putVar(t, st, "A", "1")
	putVar(t, st, "B", "2")

	if err := st.SetDescription(ctx, a, "what A is for", AgentAuthor("node")); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}
	if _, err := st.AddNote(ctx, a, "private", OwnerAuthor()); err != nil {
		t.Fatalf("AddNote: %v", err)
	}

	got, err := st.EntryAnnotations(ctx, defaultScope())
	if err != nil {
		t.Fatalf("EntryAnnotations: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1 (B has nothing to say)", len(got))
	}
	if got["A"].Description != "what A is for" || got["A"].Notes != 1 {
		t.Fatalf("A = %+v", got["A"])
	}
	if got["A"].Author != AuthorAgent || got["A"].AuthorComm != "node" {
		t.Fatalf("provenance = %+v", got["A"])
	}
}

// A listing is readable without a credential, so its descriptions and its note
// COUNTS must survive locking — and the note text must not appear in it at all.
func TestEntryAnnotations_WorkWhileLocked(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	a := putVar(t, st, "A", "1")
	if err := st.SetDescription(ctx, a, "visible", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}
	if _, err := st.AddNote(ctx, a, "invisible", OwnerAuthor()); err != nil {
		t.Fatalf("AddNote: %v", err)
	}
	st.Lock()

	got, err := st.EntryAnnotations(ctx, defaultScope())
	if err != nil {
		t.Fatalf("EntryAnnotations while locked: %v", err)
	}
	if got["A"].Description != "visible" || got["A"].Notes != 1 {
		t.Fatalf("A = %+v", got["A"])
	}
}

// An override's own description wins over the one on the row it shadows —
// the same precedence the value itself follows.
func TestEntryAnnotations_OverrideWinsOverInherited(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.CreateEnv(ctx, DefaultProjectName, "prod"); err != nil {
		t.Fatalf("CreateEnv: %v", err)
	}
	prod := Scope{Project: DefaultProjectName, Env: "prod"}

	shared := putVar(t, st, "SHARED", "default value")
	if err := st.SetDescription(ctx, shared, "the shared one", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}

	// Inherited: prod sees default's description.
	got, err := st.EntryAnnotations(ctx, prod)
	if err != nil {
		t.Fatalf("EntryAnnotations: %v", err)
	}
	if got["SHARED"].Description != "the shared one" {
		t.Fatalf("inherited = %q", got["SHARED"].Description)
	}

	// Overridden: prod's own row and its own description.
	if err := st.PutEnvVar(ctx, prod, "SHARED", []byte("prod value"), PutOpt{}); err != nil {
		t.Fatalf("PutEnvVar: %v", err)
	}
	own, err := st.EntryObjectRef(ctx, prod, "SHARED")
	if err != nil {
		t.Fatalf("EntryObjectRef: %v", err)
	}
	if err := st.SetDescription(ctx, own, "the prod one", OwnerAuthor()); err != nil {
		t.Fatalf("SetDescription: %v", err)
	}
	if got, err = st.EntryAnnotations(ctx, prod); err != nil {
		t.Fatalf("EntryAnnotations: %v", err)
	}
	if got["SHARED"].Description != "the prod one" {
		t.Fatalf("override = %q", got["SHARED"].Description)
	}
	// default itself is unchanged.
	if got, err = st.EntryAnnotations(ctx, defaultScope()); err != nil {
		t.Fatalf("EntryAnnotations: %v", err)
	}
	if got["SHARED"].Description != "the shared one" {
		t.Fatalf("default = %q", got["SHARED"].Description)
	}
}

// ---- configurable limits -------------------------------------------------

func TestAnnotationLimits_AreConfigurable(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	ref := putVar(t, st, "API_KEY", "v")

	st.SetAnnotationLimits(AnnotationLimits{Description: 10, Note: 12, NotesPerObject: 1})

	if err := st.SetDescription(ctx, ref, "0123456789A", OwnerAuthor()); err == nil {
		t.Fatal("want an error past the configured description limit")
	}
	if err := st.SetDescription(ctx, ref, "0123456789", OwnerAuthor()); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	if _, err := st.AddNote(ctx, ref, "0123456789ABC", OwnerAuthor()); err == nil {
		t.Fatal("want an error past the configured note limit")
	}
	if _, err := st.AddNote(ctx, ref, "first", OwnerAuthor()); err != nil {
		t.Fatalf("first note: %v", err)
	}
	if _, err := st.AddNote(ctx, ref, "second", OwnerAuthor()); !errors.Is(err, ErrTooManyNotes) {
		t.Fatalf("past the per-object cap: %v, want ErrTooManyNotes", err)
	}
}

// An unset field keeps the built-in default rather than becoming a cap of
// zero, which would refuse every annotation.
func TestAnnotationLimits_ZeroKeepsTheDefault(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	ref := putVar(t, st, "API_KEY", "v")

	st.SetAnnotationLimits(AnnotationLimits{Description: 10})
	if err := st.SetDescription(ctx, ref, "0123456789", OwnerAuthor()); err != nil {
		t.Fatalf("configured limit: %v", err)
	}
	if _, err := st.AddNote(ctx, ref, strings.Repeat("x", MaxNoteLen), OwnerAuthor()); err != nil {
		t.Fatalf("an unset note limit must keep the default: %v", err)
	}
	got := ResolveAnnotationLimits(AnnotationLimits{Description: 10})
	if got.Note != MaxNoteLen || got.NotesPerObject != MaxNotesPerObject || got.Description != 10 {
		t.Fatalf("ResolveAnnotationLimits = %+v", got)
	}
}
