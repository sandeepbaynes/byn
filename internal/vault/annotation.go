package vault

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// Commentary on the things in a vault.
//
// byn has always been able to tell a tool WHICH variables exist. It has never
// been able to tell it what they are for, so an agent either guessed or asked.
// A description closes that: plaintext, no credential, readable while the vault
// is locked, because a caller that has not authenticated is exactly who needs
// it. A note is the opposite — the owner's own writing, sealed like a value.
//
// The split is the whole design. Text an agent may read cannot be encrypted,
// and text the owner wants private cannot be readable by an agent, so one field
// could not be both. The rule for deciding: if you would mind an agent reading
// it, it is a note.

// ObjectType names a kind of thing an annotation can be attached to. Every
// object in byn is annotatable; the enum is closed so a typo cannot invent a
// namespace that nothing ever reads back.
type ObjectType string

// The annotatable object types.
const (
	ObjectVault   ObjectType = "vault"
	ObjectProject ObjectType = "project"
	ObjectEnv     ObjectType = "env"
	ObjectEntry   ObjectType = "entry"
	ObjectTrust   ObjectType = "trust"
	ObjectRun     ObjectType = "run"
	ObjectPasskey ObjectType = "passkey"
)

// Annotation kinds.
const (
	KindDescription = "description"
	KindNote        = "note"
)

// Annotation authors. An authenticated session is the owner; anything else is
// an agent, and which it was is kept forever because a description is an
// instruction channel and its provenance is the only thing a reader has.
const (
	AuthorOwner = "owner"
	AuthorAgent = "agent"
)

// Key domains for a note. A description has none — it is a column.
const (
	keyDomainNone     = "none"
	keyDomainEnv      = "env"
	keyDomainAuthored = "authored"
	keyDomainVault    = "vault"
)

// Annotation size limits. A description longer than a paragraph is not
// instructions, and an unbounded plaintext column on a surface readable without
// a credential is somewhere to stash a payload.
//
// These are the built-in defaults. They are configurable per installation
// ([annotations] in the config file); the daemon calls SetAnnotationLimits
// after reading it, and the store falls back to these when it has not.
const (
	MaxDescriptionLen = 4 << 10
	MaxNoteLen        = 64 << 10
	MaxNotesPerObject = 200
)

// AnnotationLimits are the configured caps.
type AnnotationLimits struct {
	Description    int
	Note           int
	NotesPerObject int
}

// ResolveAnnotationLimits fills in the built-in default for every unset field,
// so two limit sets can be compared for "did this actually change" without one
// side's unset zero reading as a difference.
func ResolveAnnotationLimits(l AnnotationLimits) AnnotationLimits {
	return AnnotationLimits{
		Description:    orDefault(l.Description, MaxDescriptionLen),
		Note:           orDefault(l.Note, MaxNoteLen),
		NotesPerObject: orDefault(l.NotesPerObject, MaxNotesPerObject),
	}
}

// SetAnnotationLimits applies the configured caps. A zero or negative field
// keeps the built-in default for that limit, so a partially-filled config
// cannot silently forbid every annotation.
func (s *Store) SetAnnotationLimits(l AnnotationLimits) {
	s.annotationLimits = ResolveAnnotationLimits(l)
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func (s *Store) maxDescription() int {
	return orDefault(s.annotationLimits.Description, MaxDescriptionLen)
}
func (s *Store) maxNote() int { return orDefault(s.annotationLimits.Note, MaxNoteLen) }
func (s *Store) maxNotesPerObject() int {
	return orDefault(s.annotationLimits.NotesPerObject, MaxNotesPerObject)
}

// ErrTooManyNotes is returned when an object has hit MaxNotesPerObject.
var ErrTooManyNotes = errors.New("vault: too many notes on this object")

// ErrNotAnnotatable is returned for an object reference that names no type byn
// knows, or that carries no id.
var ErrNotAnnotatable = errors.New("vault: not an annotatable object")

// ObjectRef identifies the thing being annotated.
//
// ID must be a surrogate id that is never handed out twice — every source table
// uses AUTOINCREMENT, which SQLite guarantees is monotonic. A natural key would
// be reusable, and re-trusting the same .byn path or recreating a project of
// the same name must not inherit the dead one's notes.
//
// ProjectID and EnvID are set for an entry, and name the scope whose key seals
// notes on it. They are zero for everything else, which seals under the vault
// key instead.
type ObjectRef struct {
	Type      ObjectType
	ID        string
	ProjectID int64
	EnvID     int64
}

// EntryObject builds a reference to one entry, bound to the scope its notes derive
// their key from.
func EntryObject(entryID, projectID, envID int64) ObjectRef {
	return ObjectRef{
		Type:      ObjectEntry,
		ID:        strconv.FormatInt(entryID, 10),
		ProjectID: projectID,
		EnvID:     envID,
	}
}

// Ref builds a reference to a non-scoped object from its integer id.
func Ref(t ObjectType, id int64) ObjectRef {
	return ObjectRef{Type: t, ID: strconv.FormatInt(id, 10)}
}

func (r ObjectRef) validate() error {
	switch r.Type {
	case ObjectVault, ObjectProject, ObjectEnv, ObjectEntry, ObjectTrust, ObjectRun, ObjectPasskey:
	default:
		return fmt.Errorf("%w: unknown type %q", ErrNotAnnotatable, r.Type)
	}
	if r.ID == "" {
		return fmt.Errorf("%w: empty id", ErrNotAnnotatable)
	}
	return nil
}

// Author records who wrote an annotation. Comm is the caller's process name for
// an agent, and empty for the owner.
type Author struct {
	Kind string
	Comm string
}

// OwnerAuthor is the author of anything written through an authenticated
// session.
func OwnerAuthor() Author { return Author{Kind: AuthorOwner} }

// AgentAuthor names an unattended caller by its process name.
func AgentAuthor(comm string) Author { return Author{Kind: AuthorAgent, Comm: comm} }

func (a Author) validate() error {
	if a.Kind != AuthorOwner && a.Kind != AuthorAgent {
		return fmt.Errorf("vault: unknown annotation author %q", a.Kind)
	}
	return nil
}

// Annotation is one description or note, as read back.
type Annotation struct {
	ID         int64
	Object     ObjectRef
	Kind       string
	Body       string
	Author     string
	AuthorComm string
	CreatedAt  int64
	UpdatedAt  int64
	// DeletedAt is when the annotation was removed, 0 while it is live. Only
	// the *IncludingRemoved listings return removed ones.
	DeletedAt int64
}

// AnnotationVersion is one point in an annotation's history. Body is empty for
// a delete, which records that the text was removed and by whom.
type AnnotationVersion struct {
	VersionNo  int
	Op         string
	Body       string
	Author     string
	AuthorComm string
	CreatedAt  int64
}

// --- descriptions: plaintext, no key, readable (and writable) while locked ---

// SetDescription writes the one description an object may have, replacing any
// current text and keeping the old in history.
//
// It needs no key, so it works on a locked vault. That is deliberate: the field
// exists so tools know how to use a value, and having to expose every secret in
// the vault to reword a sentence would be backwards. Authorization — who may
// call this at all — is the daemon's job, not the store's.
func (s *Store) SetDescription(ctx context.Context, ref ObjectRef, text string, author Author) error {
	if err := ref.validate(); err != nil {
		return err
	}
	if err := author.validate(); err != nil {
		return err
	}
	if lim := s.maxDescription(); len(text) > lim {
		return fmt.Errorf("vault: description too large (%d > %d)", len(text), lim)
	}
	if strings.TrimSpace(text) == "" {
		return errors.New("vault: description is empty")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := nowUnix()
	var id int64
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM annotations
		  WHERE object_type = ? AND object_id = ? AND kind = 'description' AND deleted_at IS NULL`,
		string(ref.Type), ref.ID).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		uid, uerr := newAnnotationUID()
		if uerr != nil {
			return uerr
		}
		res, ierr := tx.ExecContext(ctx,
			`INSERT INTO annotations
				(uid, object_type, object_id, kind, body, key_domain, author, author_comm, created_at, updated_at)
			 VALUES (?, ?, ?, 'description', ?, ?, ?, ?, ?, ?)`,
			uid, string(ref.Type), ref.ID, text, keyDomainNone, author.Kind, nullComm(author), now, now)
		if ierr != nil {
			return ierr
		}
		if id, ierr = res.LastInsertId(); ierr != nil {
			return ierr
		}
		if verr := appendVersion(ctx, tx, id, "create", text, nil, author, now); verr != nil {
			return verr
		}
	case err != nil:
		return err
	default:
		if _, uerr := tx.ExecContext(ctx,
			`UPDATE annotations SET body = ?, author = ?, author_comm = ?, updated_at = ? WHERE id = ?`,
			text, author.Kind, nullComm(author), now, id); uerr != nil {
			return uerr
		}
		if verr := appendVersion(ctx, tx, id, "edit", text, nil, author, now); verr != nil {
			return verr
		}
	}
	return tx.Commit()
}

// GetDescription returns an object's description. Returns ErrNotFound when it
// has none. No key required.
func (s *Store) GetDescription(ctx context.Context, ref ObjectRef) (Annotation, error) {
	if err := ref.validate(); err != nil {
		return Annotation{}, err
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT id, body, author, COALESCE(author_comm, ''), created_at, updated_at
		   FROM annotations
		  WHERE object_type = ? AND object_id = ? AND kind = 'description' AND deleted_at IS NULL`,
		string(ref.Type), ref.ID)
	a := Annotation{Object: ref, Kind: KindDescription}
	var body sql.NullString
	if err := row.Scan(&a.ID, &body, &a.Author, &a.AuthorComm, &a.CreatedAt, &a.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Annotation{}, ErrNotFound
		}
		return Annotation{}, err
	}
	a.Body = body.String
	return a, nil
}

// Descriptions returns the descriptions for many objects of one type, keyed by
// object id. It is the batch form a list view needs: one query for a whole
// listing rather than one per row.
func (s *Store) Descriptions(ctx context.Context, t ObjectType, ids []string) (map[string]Annotation, error) {
	out := make(map[string]Annotation, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	args := make([]any, 0, len(ids)+1)
	args = append(args, string(t))
	ph := make([]string, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args = append(args, id)
	}
	//nolint:gosec // G202: placeholders only, every id is a bound parameter.
	q := `SELECT object_id, id, body, author, COALESCE(author_comm, ''), created_at, updated_at
	        FROM annotations
	       WHERE object_type = ? AND kind = 'description' AND deleted_at IS NULL
	         AND object_id IN (` + strings.Join(ph, ",") + `)`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var objID string
		var body sql.NullString
		a := Annotation{Object: ObjectRef{Type: t}, Kind: KindDescription}
		if err := rows.Scan(&objID, &a.ID, &body, &a.Author, &a.AuthorComm, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		a.Object.ID = objID
		a.Body = body.String
		out[objID] = a
	}
	return out, rows.Err()
}

// --- notes: encrypted, need the key ---

// AddNote appends a note to an object, sealed under the key covering it.
// Requires an unlocked vault.
func (s *Store) AddNote(ctx context.Context, ref ObjectRef, text string, author Author) (int64, error) {
	vk := s.snapshotVaultKey()
	if vk == nil {
		return 0, ErrLocked
	}
	defer zero(vk)
	return s.addNoteWithVaultKey(ctx, vk, ref, text, author)
}

// AddNoteWithPassword is AddNote for a locked vault, proving who is asking with
// the master password rather than unlocking. The note is sealed exactly as it
// would be with the vault open.
func (s *Store) AddNoteWithPassword(ctx context.Context, password []byte, ref ObjectRef,
	text string, author Author) (int64, error) {

	vk, err := s.unwrapForAnnotation(password)
	if err != nil {
		return 0, err
	}
	defer zero(vk)
	return s.addNoteWithVaultKey(ctx, vk, ref, text, author)
}

// AddNoteAuthored appends a note using an already-unsealed authored key, so an
// unattended caller can annotate what it creates while the vault is locked and
// read its own note back later. It carries the same trade authored.go states:
// such a note is protected by this machine rather than by the master password.
func (s *Store) AddNoteAuthored(ctx context.Context, ref ObjectRef, text string,
	authoredKey []byte, author Author) (int64, error) {

	if len(authoredKey) == 0 {
		return 0, ErrLocked
	}
	if ref.Type != ObjectEntry {
		return 0, fmt.Errorf("%w: the authored key covers entries only", ErrNotAnnotatable)
	}
	return s.addNote(ctx, ref, text, author, authoredKey, keyDomainAuthored)
}

func (s *Store) addNoteWithVaultKey(ctx context.Context, vaultKey []byte, ref ObjectRef,
	text string, author Author) (int64, error) {

	base, domain, err := s.annotationBaseKey(vaultKey, ref)
	if err != nil {
		return 0, err
	}
	defer zero(base)
	return s.addNote(ctx, ref, text, author, base, domain)
}

func (s *Store) addNote(ctx context.Context, ref ObjectRef, text string, author Author,
	baseKey []byte, domain string) (int64, error) {

	if err := ref.validate(); err != nil {
		return 0, err
	}
	if err := author.validate(); err != nil {
		return 0, err
	}
	if lim := s.maxNote(); len(text) > lim {
		return 0, fmt.Errorf("vault: note too large (%d > %d)", len(text), lim)
	}
	if strings.TrimSpace(text) == "" {
		return 0, errors.New("vault: note is empty")
	}

	n, err := s.noteCount(ctx, ref)
	if err != nil {
		return 0, err
	}
	if n >= s.maxNotesPerObject() {
		return 0, ErrTooManyNotes
	}

	uid, err := newAnnotationUID()
	if err != nil {
		return 0, err
	}
	ct, err := s.sealNote(baseKey, ref, domain, uid, text)
	if err != nil {
		return 0, err
	}

	now := nowUnix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`INSERT INTO annotations
			(uid, object_type, object_id, kind, body_enc, key_domain, author, author_comm, created_at, updated_at)
		 VALUES (?, ?, ?, 'note', ?, ?, ?, ?, ?, ?)`,
		uid, string(ref.Type), ref.ID, ct, domain, author.Kind, nullComm(author), now, now)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := appendVersion(ctx, tx, id, "create", "", ct, author, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

// ListNotes returns an object's notes, newest first. Requires an unlocked
// vault: this is the owner's private writing, and reading it is the one thing
// the key is for.
func (s *Store) ListNotes(ctx context.Context, ref ObjectRef) ([]Annotation, error) {
	vk := s.snapshotVaultKey()
	if vk == nil {
		return nil, ErrLocked
	}
	defer zero(vk)
	return s.listNotesWithVaultKey(ctx, vk, ref, false)
}

// ListNotesWithPassword is ListNotes for a locked vault.
func (s *Store) ListNotesWithPassword(ctx context.Context, password []byte, ref ObjectRef) ([]Annotation, error) {
	vk, err := s.unwrapForAnnotation(password)
	if err != nil {
		return nil, err
	}
	defer zero(vk)
	return s.listNotesWithVaultKey(ctx, vk, ref, false)
}

// ListNotesIncludingRemoved is ListNotes plus the notes that were removed,
// each with DeletedAt set and the text it had when it was removed. Removal is
// a tombstone precisely so this trail survives; without a listing, a removed
// note's id — and so its history — could not be found again.
func (s *Store) ListNotesIncludingRemoved(ctx context.Context, ref ObjectRef) ([]Annotation, error) {
	vk := s.snapshotVaultKey()
	if vk == nil {
		return nil, ErrLocked
	}
	defer zero(vk)
	return s.listNotesWithVaultKey(ctx, vk, ref, true)
}

// ListNotesIncludingRemovedWithPassword is ListNotesIncludingRemoved for a
// locked vault.
func (s *Store) ListNotesIncludingRemovedWithPassword(ctx context.Context, password []byte, ref ObjectRef) ([]Annotation, error) {
	vk, err := s.unwrapForAnnotation(password)
	if err != nil {
		return nil, err
	}
	defer zero(vk)
	return s.listNotesWithVaultKey(ctx, vk, ref, true)
}

func (s *Store) listNotesWithVaultKey(ctx context.Context, vaultKey []byte, ref ObjectRef, includeRemoved bool) ([]Annotation, error) {
	if err := ref.validate(); err != nil {
		return nil, err
	}
	live := " AND deleted_at IS NULL"
	if includeRemoved {
		live = ""
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, uid, body_enc, key_domain, author, COALESCE(author_comm, ''), created_at, updated_at,
		        COALESCE(deleted_at, 0)
		   FROM annotations
		  WHERE object_type = ? AND object_id = ? AND kind = 'note'`+live+`
		  ORDER BY created_at DESC, id DESC`,
		string(ref.Type), ref.ID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Annotation
	for rows.Next() {
		var (
			a      = Annotation{Object: ref, Kind: KindNote}
			uid    []byte
			ct     []byte
			domain string
		)
		if err := rows.Scan(&a.ID, &uid, &ct, &domain, &a.Author, &a.AuthorComm, &a.CreatedAt, &a.UpdatedAt, &a.DeletedAt); err != nil {
			return nil, err
		}
		text, err := s.openNote(vaultKey, ref, domain, uid, ct)
		if err != nil {
			return nil, err
		}
		a.Body = text
		out = append(out, a)
	}
	return out, rows.Err()
}

// NoteCount reports how many notes an object carries. It reads no text, so it
// works on a locked vault — that is what lets a locked listing show that notes
// exist without showing what they say.
func (s *Store) NoteCount(ctx context.Context, ref ObjectRef) (int, error) {
	if err := ref.validate(); err != nil {
		return 0, err
	}
	return s.noteCount(ctx, ref)
}

func (s *Store) noteCount(ctx context.Context, ref ObjectRef) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM annotations
		  WHERE object_type = ? AND object_id = ? AND kind = 'note' AND deleted_at IS NULL`,
		string(ref.Type), ref.ID).Scan(&n)
	return n, err
}

// EditNote replaces a note's text, keeping the old in history.
func (s *Store) EditNote(ctx context.Context, ref ObjectRef, id int64, text string, author Author) error {
	vk := s.snapshotVaultKey()
	if vk == nil {
		return ErrLocked
	}
	defer zero(vk)
	return s.editNoteWithVaultKey(ctx, vk, ref, id, text, author)
}

// EditNoteWithPassword is EditNote for a locked vault.
func (s *Store) EditNoteWithPassword(ctx context.Context, password []byte, ref ObjectRef,
	id int64, text string, author Author) error {

	vk, err := s.unwrapForAnnotation(password)
	if err != nil {
		return err
	}
	defer zero(vk)
	return s.editNoteWithVaultKey(ctx, vk, ref, id, text, author)
}

func (s *Store) editNoteWithVaultKey(ctx context.Context, vaultKey []byte, ref ObjectRef,
	id int64, text string, author Author) error {

	if err := ref.validate(); err != nil {
		return err
	}
	if err := author.validate(); err != nil {
		return err
	}
	if lim := s.maxNote(); len(text) > lim {
		return fmt.Errorf("vault: note too large (%d > %d)", len(text), lim)
	}
	if strings.TrimSpace(text) == "" {
		return errors.New("vault: note is empty")
	}

	var (
		uid    []byte
		domain string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT uid, key_domain FROM annotations
		  WHERE id = ? AND object_type = ? AND object_id = ? AND kind = 'note' AND deleted_at IS NULL`,
		id, string(ref.Type), ref.ID).Scan(&uid, &domain)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}

	base, err := s.baseKeyForDomain(vaultKey, ref, domain)
	if err != nil {
		return err
	}
	defer zero(base)
	ct, err := s.sealNote(base, ref, domain, uid, text)
	if err != nil {
		return err
	}

	now := nowUnix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`UPDATE annotations SET body_enc = ?, updated_at = ? WHERE id = ?`, ct, now, id); err != nil {
		return err
	}
	if err := appendVersion(ctx, tx, id, "edit", "", ct, author, now); err != nil {
		return err
	}
	return tx.Commit()
}

// RemoveAnnotation deletes one annotation — as a tombstone. The live row goes
// away; every version of its text stays.
//
// There is no purge, on purpose. The reason history is kept at all is that a
// description or note changed to mislead a later reader has to be traceable,
// and a purge would hand exactly that case the tool it needs. The text goes
// when the object it describes goes, and not before.
func (s *Store) RemoveAnnotation(ctx context.Context, ref ObjectRef, id int64, author Author) error {
	if err := ref.validate(); err != nil {
		return err
	}
	if err := author.validate(); err != nil {
		return err
	}
	now := nowUnix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`UPDATE annotations SET deleted_at = ?, updated_at = ?
		  WHERE id = ? AND object_type = ? AND object_id = ? AND deleted_at IS NULL`,
		now, now, id, string(ref.Type), ref.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	if err := appendVersion(ctx, tx, id, "delete", "", nil, author, now); err != nil {
		return err
	}
	return tx.Commit()
}

// AnnotationHistory returns every version of one annotation, oldest first.
//
// A note's versions are decrypted, so this needs an unlocked vault when the
// annotation is a note; a description's history needs nothing. This is the
// answer to "who changed this, to what, and when" — the question a description
// that told an agent the wrong thing leaves behind.
func (s *Store) AnnotationHistory(ctx context.Context, ref ObjectRef, id int64) ([]AnnotationVersion, error) {
	if err := ref.validate(); err != nil {
		return nil, err
	}
	var (
		kind   string
		uid    []byte
		domain string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT kind, uid, key_domain FROM annotations
		  WHERE id = ? AND object_type = ? AND object_id = ?`,
		id, string(ref.Type), ref.ID).Scan(&kind, &uid, &domain)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	var vaultKey []byte
	if kind == KindNote {
		vaultKey = s.snapshotVaultKey()
		if vaultKey == nil {
			return nil, ErrLocked
		}
		defer zero(vaultKey)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT version_no, op, body, body_enc, author, COALESCE(author_comm, ''), created_at
		   FROM annotation_versions WHERE annotation_id = ? ORDER BY version_no`, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []AnnotationVersion
	for rows.Next() {
		var (
			v    AnnotationVersion
			body sql.NullString
			ct   []byte
		)
		if err := rows.Scan(&v.VersionNo, &v.Op, &body, &ct, &v.Author, &v.AuthorComm, &v.CreatedAt); err != nil {
			return nil, err
		}
		switch {
		case len(ct) > 0:
			text, derr := s.openNote(vaultKey, ref, domain, uid, ct)
			if derr != nil {
				return nil, derr
			}
			v.Body = text
		default:
			v.Body = body.String
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// --- cascade ---

// DeleteAnnotationsFor removes every annotation on the given objects, history
// included. A polymorphic table carries no foreign key, so each delete path has
// to reach annotations itself — that is the standing obligation this exists to
// satisfy, and doctor sweeps for anything that got missed.
func (s *Store) DeleteAnnotationsFor(ctx context.Context, t ObjectType, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	return deleteAnnotationsFor(ctx, s.db, t, ids...)
}

type execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func deleteAnnotationsFor(ctx context.Context, db execer, t ObjectType, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	args := make([]any, 0, len(ids)+1)
	args = append(args, string(t))
	ph := make([]string, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args = append(args, id)
	}
	//nolint:gosec // G202: placeholders only, every id is a bound parameter.
	q := `DELETE FROM annotations WHERE object_type = ? AND object_id IN (` + strings.Join(ph, ",") + `)`
	_, err := db.ExecContext(ctx, q, args...)
	return err
}

// orphanAnnotationWhere matches annotations whose object is gone. It is shared
// by the sweep that runs with every delete and by doctor's report, so the two
// can never disagree about what an orphan is.
//
// trust records live outside this database, so they are absent here and are
// reached by the explicit DeleteAnnotationsFor call on the untrust path.
const orphanAnnotationWhere = `
	   (object_type = 'project' AND CAST(object_id AS INTEGER) NOT IN (SELECT id FROM projects))
	OR (object_type = 'env'     AND CAST(object_id AS INTEGER) NOT IN (SELECT id FROM envs))
	OR (object_type = 'entry'   AND CAST(object_id AS INTEGER) NOT IN (SELECT id FROM entries))
	OR (object_type = 'run'     AND CAST(object_id AS INTEGER) NOT IN (SELECT id FROM exec_runs))
	OR (object_type = 'passkey' AND CAST(object_id AS INTEGER) NOT IN (SELECT id FROM passkey))`

// sweepOrphanAnnotations removes annotations left behind by a delete.
//
// Running this rather than collecting ids beforehand is what makes the fan-out
// correct: deleting a project takes its envs and entries with it through the
// foreign keys, and one statement afterwards reaches all three levels. It runs
// inside the caller's transaction so a delete and its cleanup are one event.
func sweepOrphanAnnotations(ctx context.Context, db execer) error {
	_, err := db.ExecContext(ctx, `DELETE FROM annotations WHERE`+orphanAnnotationWhere)
	return err
}

// deleteAndSweep runs one delete and clears the annotations it orphaned, in a
// single transaction, and reports how many rows the delete itself removed.
func (s *Store) deleteAndSweep(ctx context.Context, query string, args ...any) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n > 0 {
		if err := sweepOrphanAnnotations(ctx, tx); err != nil {
			return 0, err
		}
	}
	return n, tx.Commit()
}

// OrphanAnnotations counts annotations whose object no longer exists — the
// backstop for a delete path that forgot to call DeleteAnnotationsFor. Ids are
// never reused, so an orphan is inert rather than dangerous; it is still a
// deleted thing's notes outliving it, which doctor should say out loud.
func (s *Store) OrphanAnnotations(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM annotations WHERE`+orphanAnnotationWhere).Scan(&n)
	return n, err
}

// SweepOrphanAnnotations deletes what OrphanAnnotations counts, and reports how
// many rows went.
func (s *Store) SweepOrphanAnnotations(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM annotations WHERE`+orphanAnnotationWhere)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// --- internals ---

func newAnnotationUID() ([]byte, error) {
	uid := make([]byte, 16)
	if _, err := rand.Read(uid); err != nil {
		return nil, fmt.Errorf("vault: rand: %w", err)
	}
	return uid, nil
}

func nullComm(a Author) any {
	if a.Comm == "" {
		return nil
	}
	return a.Comm
}

func appendVersion(ctx context.Context, tx *sql.Tx, annotationID int64, op, body string,
	bodyEnc []byte, author Author, now int64) error {

	var next int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version_no), 0) + 1 FROM annotation_versions WHERE annotation_id = ?`,
		annotationID).Scan(&next); err != nil {
		return err
	}
	var (
		bodyArg any
		encArg  any
	)
	if body != "" {
		bodyArg = body
	}
	if len(bodyEnc) > 0 {
		encArg = bodyEnc
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO annotation_versions
			(annotation_id, version_no, body, body_enc, op, author, author_comm, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		annotationID, next, bodyArg, encArg, op, author.Kind, nullComm(author), now)
	return err
}

// annotationBaseKey picks the key lineage a note on ref derives from: the
// scope key for an entry, the vault key for everything else.
func (s *Store) annotationBaseKey(vaultKey []byte, ref ObjectRef) ([]byte, string, error) {
	if ref.Type == ObjectEntry && ref.ProjectID > 0 && ref.EnvID > 0 {
		k, err := s.EnvKey(vaultKey, ref.ProjectID, ref.EnvID)
		if err != nil {
			return nil, "", err
		}
		return k, keyDomainEnv, nil
	}
	k := make([]byte, len(vaultKey))
	copy(k, vaultKey)
	return k, keyDomainVault, nil
}

// baseKeyForDomain reproduces the base key a stored note was sealed under.
// The authored domain is absent on purpose: its key is not derivable from the
// vault key alone at this layer, and an authored note is edited through the
// caller that holds it.
func (s *Store) baseKeyForDomain(vaultKey []byte, ref ObjectRef, domain string) ([]byte, error) {
	switch domain {
	case keyDomainEnv:
		return s.EnvKey(vaultKey, ref.ProjectID, ref.EnvID)
	case keyDomainVault:
		k := make([]byte, len(vaultKey))
		copy(k, vaultKey)
		return k, nil
	case keyDomainAuthored:
		return nil, errAuthoredKeyUnsupported
	default:
		return nil, fmt.Errorf("vault: unknown annotation key domain %q", domain)
	}
}

// annotationAAD is a note's stable identity: it is the HKDF context that
// derives the key AND the AEAD AAD. Both uses matter — the uid keeps two notes
// on the same object from sharing a key, and binding the object and kind means
// a ciphertext moved anywhere else fails to open rather than decrypting into
// the wrong place.
func (s *Store) annotationAAD(ref ObjectRef, domain string, uid []byte) []byte {
	const sep = 0x1F
	b := make([]byte, 0, len(s.vaultID)+len(ref.Type)+len(ref.ID)+len(domain)+2*len(uid)+16)
	b = append(b, s.vaultID...)
	b = append(b, sep)
	b = append(b, ref.Type...)
	b = append(b, sep)
	b = append(b, ref.ID...)
	b = append(b, sep)
	b = append(b, KindNote...)
	b = append(b, sep)
	b = append(b, domain...)
	b = append(b, sep)
	b = append(b, hex.EncodeToString(uid)...)
	return b
}

func (s *Store) sealNote(baseKey []byte, ref ObjectRef, domain string, uid []byte, text string) ([]byte, error) {
	aad := s.annotationAAD(ref, domain, uid)
	k, err := vcrypto.DeriveAnnotationKey(baseKey, aad)
	if err != nil {
		return nil, err
	}
	defer zero(k)
	ct, err := vcrypto.EncryptWithAAD(k, []byte(text), aad)
	if err != nil {
		return nil, fmt.Errorf("vault: encrypt note: %w", err)
	}
	return ct, nil
}

func (s *Store) openNote(vaultKey []byte, ref ObjectRef, domain string, uid, ct []byte) (string, error) {
	base, err := s.baseKeyForDomain(vaultKey, ref, domain)
	if err != nil {
		return "", err
	}
	defer zero(base)
	return s.openNoteWithBase(base, ref, domain, uid, ct)
}

func (s *Store) openNoteWithBase(baseKey []byte, ref ObjectRef, domain string, uid, ct []byte) (string, error) {
	aad := s.annotationAAD(ref, domain, uid)
	k, err := vcrypto.DeriveAnnotationKey(baseKey, aad)
	if err != nil {
		return "", err
	}
	defer zero(k)
	pt, err := vcrypto.DecryptWithAAD(k, ct, aad)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// ListNotesAuthored reads back notes an unattended caller wrote under the
// authored key, without the vault key.
func (s *Store) ListNotesAuthored(ctx context.Context, ref ObjectRef, authoredKey []byte) ([]Annotation, error) {
	if len(authoredKey) == 0 {
		return nil, ErrLocked
	}
	if err := ref.validate(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, uid, body_enc, author, COALESCE(author_comm, ''), created_at, updated_at
		   FROM annotations
		  WHERE object_type = ? AND object_id = ? AND kind = 'note'
		    AND key_domain = 'authored' AND deleted_at IS NULL
		  ORDER BY created_at DESC, id DESC`,
		string(ref.Type), ref.ID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Annotation
	for rows.Next() {
		a := Annotation{Object: ref, Kind: KindNote}
		var uid, ct []byte
		if err := rows.Scan(&a.ID, &uid, &ct, &a.Author, &a.AuthorComm, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		text, err := s.openNoteWithBase(authoredKey, ref, keyDomainAuthored, uid, ct)
		if err != nil {
			return nil, err
		}
		a.Body = text
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) unwrapForAnnotation(password []byte) ([]byte, error) {
	wrapped, err := os.ReadFile(filepath.Join(s.dir, wrappedFilename)) // #nosec G304 -- path is store-configured
	if err != nil {
		return nil, fmt.Errorf("vault: read wrapped key: %w", err)
	}
	return vcrypto.Unwrap(password, wrapped)
}

// --- resolving an object the caller named ---

// EntryObjectRef resolves one env var in scope to the object its annotations
// hang on, following inheritance the same way a read does — so annotating a
// name that a non-default env inherits annotates the row the value actually
// comes from, rather than inventing a second object for the same variable.
func (s *Store) EntryObjectRef(ctx context.Context, scope Scope, name string) (ObjectRef, error) {
	if err := scope.Validate(); err != nil {
		return ObjectRef{}, err
	}
	if err := validateEntryName(name); err != nil {
		return ObjectRef{}, err
	}
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return ObjectRef{}, err
	}
	_, rowEnvID, found, err := s.fetchEnvVarInherited(ctx, projectID, envID, scope.Env, name)
	if err != nil {
		return ObjectRef{}, err
	}
	if !found {
		return ObjectRef{}, ErrNotFound
	}
	var id int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT id FROM entries WHERE project_id = ? AND env_id = ? AND kind = 'env_var' AND name = ?`,
		projectID, rowEnvID, name).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ObjectRef{}, ErrNotFound
		}
		return ObjectRef{}, err
	}
	return EntryObject(id, projectID, rowEnvID), nil
}

// ProjectObjectRef resolves a project by name.
func (s *Store) ProjectObjectRef(ctx context.Context, project string) (ObjectRef, error) {
	if err := ValidateProjectName(project); err != nil {
		return ObjectRef{}, err
	}
	id, err := s.projectIDByName(ctx, project)
	if err != nil {
		return ObjectRef{}, err
	}
	return Ref(ObjectProject, id), nil
}

// EnvObjectRef resolves one env within a project.
func (s *Store) EnvObjectRef(ctx context.Context, project, env string) (ObjectRef, error) {
	if err := ValidateProjectName(project); err != nil {
		return ObjectRef{}, err
	}
	if err := ValidateEnvName(env); err != nil {
		return ObjectRef{}, err
	}
	projectID, err := s.projectIDByName(ctx, project)
	if err != nil {
		return ObjectRef{}, err
	}
	envID, err := s.envIDByName(ctx, projectID, env)
	if err != nil {
		return ObjectRef{}, err
	}
	return Ref(ObjectEnv, envID), nil
}

// VaultObjectRef is the vault itself. Its id is the vault's own stable id, not
// its name, because a name can be changed and reused.
func (s *Store) VaultObjectRef() ObjectRef {
	return ObjectRef{Type: ObjectVault, ID: s.vaultID}
}

// EntryAnnotation is the annotation summary a listing shows for one variable:
// its description with the provenance that decides how to read it, and how
// many notes it carries. The note TEXT is absent on purpose — a listing is
// readable without a credential and notes are not.
type EntryAnnotation struct {
	Description string
	Author      string
	AuthorComm  string
	Notes       int
}

// EntryAnnotations returns the annotation summary for every env var visible in
// scope, keyed by name, resolving inheritance the way the listing does: a
// variable's own row wins over the default env's.
//
// It needs no key, so a locked listing still shows every description and the
// fact that notes exist. One query for the whole listing rather than one per
// row: a project with two hundred variables should not cost two hundred
// round-trips to say what they are for.
func (s *Store) EntryAnnotations(ctx context.Context, scope Scope) (map[string]EntryAnnotation, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return nil, err
	}
	envIDs := []int64{envID}
	if scope.Env != DefaultEnvName {
		defaultEnvID, derr := s.envIDByName(ctx, projectID, DefaultEnvName)
		if derr != nil {
			return nil, derr
		}
		envIDs = append(envIDs, defaultEnvID)
	}

	const q = `
	SELECT e.name, e.env_id,
	       COALESCE(d.body, ''), COALESCE(d.author, ''), COALESCE(d.author_comm, ''),
	       (SELECT COUNT(*) FROM annotations n
	         WHERE n.object_type = 'entry' AND n.object_id = CAST(e.id AS TEXT)
	           AND n.kind = 'note' AND n.deleted_at IS NULL)
	  FROM entries e
	  LEFT JOIN annotations d
	    ON d.object_type = 'entry' AND d.object_id = CAST(e.id AS TEXT)
	   AND d.kind = 'description' AND d.deleted_at IS NULL
	 WHERE e.project_id = ? AND e.kind = 'env_var' AND e.env_id IN (?, ?)`

	second := envIDs[0]
	if len(envIDs) > 1 {
		second = envIDs[1]
	}
	rows, err := s.db.QueryContext(ctx, q, projectID, envIDs[0], second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]EntryAnnotation)
	seenOwn := make(map[string]bool)
	for rows.Next() {
		var (
			name    string
			rowEnv  int64
			summary EntryAnnotation
		)
		if err := rows.Scan(&name, &rowEnv, &summary.Description, &summary.Author,
			&summary.AuthorComm, &summary.Notes); err != nil {
			return nil, err
		}
		own := rowEnv == envID
		if seenOwn[name] && !own {
			continue
		}
		if own {
			seenOwn[name] = true
		}
		if summary.Description == "" && summary.Notes == 0 {
			delete(out, name)
			continue
		}
		out[name] = summary
	}
	return out, rows.Err()
}
