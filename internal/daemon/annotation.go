package daemon

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// Annotations over IPC.
//
// There is no annotation permission model, on purpose. An annotation inherits
// the authorization of the operation that carries it: creating an object is
// free, changing one is gated, and so a caller working unattended may say what
// a variable is for at the moment it creates it and never again. That is
// exactly the rule the owner asked for, and it is the rule byn already enforces
// for values — a second policy surface would be a second thing to get wrong.
//
// Reading splits the same way the storage does. A description comes back to any
// caller, because a tool that has not authenticated is who it is for. A note
// needs the key, and when one is withheld the caller is told that it exists
// rather than being shown an empty list: "no notes" and "not for you" are
// different answers and a caller cannot otherwise tell them apart.

// annotationAction is the gate name annotation writes are checked against. They
// are updates: the same act as changing a value, on the same object.
const annotationAction = "update"

// authorFor names whoever is behind this call. A caller with a session, a
// password or a presence token is the owner; anything else is an agent, and
// its process name is recorded so a reader can see where a description came
// from.
func (d *Daemon) authorFor(ctx context.Context, vaultName string, password, presenceToken []byte) vault.Author {
	if d.callerIsAttended(ctx, vaultName, password, presenceToken) {
		return vault.OwnerAuthor()
	}
	return vault.AgentAuthor(callerFrom(ctx).Comm)
}

// resolveTarget turns the object a caller named into the reference annotations
// hang on.
func (d *Daemon) resolveTarget(ctx context.Context, st *vault.Store, scope vault.Scope,
	t ipc.AnnotationTarget) (vault.ObjectRef, error) {

	switch vault.ObjectType(t.Type) {
	case vault.ObjectEntry:
		return st.EntryObjectRef(ctx, scope, t.Name)
	case vault.ObjectProject:
		name := t.Name
		if name == "" {
			name = scope.Project
		}
		return st.ProjectObjectRef(ctx, name)
	case vault.ObjectEnv:
		name := t.Name
		if name == "" {
			name = scope.Env
		}
		return st.EnvObjectRef(ctx, scope.Project, name)
	case vault.ObjectVault:
		return st.VaultObjectRef(), nil
	case vault.ObjectTrust, vault.ObjectRun, vault.ObjectPasskey:
		if t.ID <= 0 {
			return vault.ObjectRef{}, fmt.Errorf("%w: %s needs an id", vault.ErrNotAnnotatable, t.Type)
		}
		return vault.Ref(vault.ObjectType(t.Type), t.ID), nil
	default:
		return vault.ObjectRef{}, fmt.Errorf("%w: unknown type %q", vault.ErrNotAnnotatable, t.Type)
	}
}

// annotationTargetLabel is what the audit log records an annotation against.
// It names the object, never the text: a description is not a secret, but the
// audit chain is mirrored off-box and there is no reason to widen what travels.
func annotationTargetLabel(t ipc.AnnotationTarget) string {
	if t.Name != "" {
		return t.Type + ":" + t.Name
	}
	if t.ID > 0 {
		return t.Type + ":" + strconv.FormatInt(t.ID, 10)
	}
	return t.Type
}

func (d *Daemon) handleAnnotationSet(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.AnnotationSetReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)

	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		return errEnv
	}
	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)

	// A description needs no key, so this is NOT gated on unlock — only on
	// auth. Changing one is an update; who is allowed to make it is the same
	// question as who may change the value it describes.
	if le := d.authorizeAction(ctx, env.ID, vaultName, scope, st, annotationAction,
		req.Password, req.PresenceToken); le != nil {
		d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.set", le)
		return le
	}

	ref, err := d.resolveTarget(ctx, st, scope, req.Target)
	if err != nil {
		resp := mapAnnotationErr(env.ID, err)
		d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.set", resp)
		return resp
	}
	author := d.authorFor(ctx, vaultName, req.Password, req.PresenceToken)

	var resp *ipc.Envelope
	if req.Clear {
		cur, gerr := st.GetDescription(ctx, ref)
		if gerr != nil {
			resp = mapAnnotationErr(env.ID, gerr)
		} else if rerr := st.RemoveAnnotation(ctx, ref, cur.ID, author); rerr != nil {
			resp = mapAnnotationErr(env.ID, rerr)
		} else {
			resp = mustResponse(env.ID, ipc.AnnotationSetResp{ID: cur.ID})
		}
		d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.remove", resp)
		return resp
	}

	if serr := st.SetDescription(ctx, ref, req.Text, author); serr != nil {
		resp = mapAnnotationErr(env.ID, serr)
	} else {
		cur, gerr := st.GetDescription(ctx, ref)
		if gerr != nil {
			resp = mapAnnotationErr(env.ID, gerr)
		} else {
			resp = mustResponse(env.ID, ipc.AnnotationSetResp{ID: cur.ID})
		}
	}
	d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.set", resp)
	return resp
}

func (d *Daemon) handleAnnotationAdd(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.AnnotationAddReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)

	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		return errEnv
	}
	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)

	if le := d.authorizeAction(ctx, env.ID, vaultName, scope, st, annotationAction,
		req.Password, req.PresenceToken); le != nil {
		d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.add", le)
		return le
	}
	ref, err := d.resolveTarget(ctx, st, scope, req.Target)
	if err != nil {
		resp := mapAnnotationErr(env.ID, err)
		d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.add", resp)
		return resp
	}

	author := d.authorFor(ctx, vaultName, req.Password, req.PresenceToken)
	var (
		id     int64
		aerr   error
		locked = st.IsLocked()
	)
	switch {
	case locked && len(req.Password) > 0:
		id, aerr = st.AddNoteWithPassword(ctx, req.Password, ref, req.Text, author)
	default:
		id, aerr = st.AddNote(ctx, ref, req.Text, author)
	}

	var resp *ipc.Envelope
	if aerr != nil {
		resp = mapAnnotationErr(env.ID, aerr)
	} else {
		resp = mustResponse(env.ID, ipc.AnnotationAddResp{ID: id})
		d.touchVault(req.Scope.Vault)
	}
	d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.add", resp)
	return resp
}

func (d *Daemon) handleAnnotationEdit(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.AnnotationEditReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)

	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		return errEnv
	}
	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)

	if le := d.authorizeAction(ctx, env.ID, vaultName, scope, st, annotationAction,
		req.Password, req.PresenceToken); le != nil {
		d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.edit", le)
		return le
	}
	ref, err := d.resolveTarget(ctx, st, scope, req.Target)
	if err != nil {
		resp := mapAnnotationErr(env.ID, err)
		d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.edit", resp)
		return resp
	}

	author := d.authorFor(ctx, vaultName, req.Password, req.PresenceToken)
	var eerr error
	if st.IsLocked() && len(req.Password) > 0 {
		eerr = st.EditNoteWithPassword(ctx, req.Password, ref, req.ID, req.Text, author)
	} else {
		eerr = st.EditNote(ctx, ref, req.ID, req.Text, author)
	}

	var resp *ipc.Envelope
	if eerr != nil {
		resp = mapAnnotationErr(env.ID, eerr)
	} else {
		resp = mustResponse(env.ID, ipc.AnnotationEditResp{})
		d.touchVault(req.Scope.Vault)
	}
	d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.edit", resp)
	return resp
}

func (d *Daemon) handleAnnotationRemove(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.AnnotationRemoveReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)

	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		return errEnv
	}
	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)

	if le := d.authorizeAction(ctx, env.ID, vaultName, scope, st, annotationAction,
		req.Password, req.PresenceToken); le != nil {
		d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.remove", le)
		return le
	}
	ref, err := d.resolveTarget(ctx, st, scope, req.Target)
	if err != nil {
		resp := mapAnnotationErr(env.ID, err)
		d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.remove", resp)
		return resp
	}

	author := d.authorFor(ctx, vaultName, req.Password, req.PresenceToken)
	var resp *ipc.Envelope
	if rerr := st.RemoveAnnotation(ctx, ref, req.ID, author); rerr != nil {
		resp = mapAnnotationErr(env.ID, rerr)
	} else {
		resp = mustResponse(env.ID, ipc.AnnotationRemoveResp{})
	}
	d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.remove", resp)
	return resp
}

func (d *Daemon) handleAnnotationList(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.AnnotationListReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)

	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		return errEnv
	}
	ref, err := d.resolveTarget(ctx, st, scope, req.Target)
	if err != nil {
		return mapAnnotationErr(env.ID, err)
	}

	var out ipc.AnnotationListResp

	// Descriptions: free. This is the half an unauthenticated tool is meant to
	// read, and gating it would defeat the point of having it in plaintext.
	if req.Kind == "" || req.Kind == vault.KindDescription {
		desc, derr := st.GetDescription(ctx, ref)
		switch {
		case derr == nil:
			out.Descriptions = append(out.Descriptions, annotationView(desc, "vault"))
		case errors.Is(derr, vault.ErrNotFound):
			// nothing to say
		default:
			return mapAnnotationErr(env.ID, derr)
		}
	}

	if req.Kind == vault.KindDescription {
		return mustResponse(env.ID, out)
	}

	count, cerr := st.NoteCount(ctx, ref)
	if cerr != nil {
		return mapAnnotationErr(env.ID, cerr)
	}
	out.NoteCount = count

	// Notes: the owner's writing. Reading one is a read of encrypted content
	// and is gated exactly like reading a value.
	//
	// How a refusal is reported depends on what was asked. A caller that asked
	// specifically for notes gets an ERROR, so it can supply a credential and
	// retry — answering "ok, nothing for you" would look like success and leave
	// it with no way to ask again. A caller that asked for everything about an
	// object (the portal panel, which also wants the description) gets what it
	// may see, with NotesWithheld set: that is a partial answer, not a failure.
	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
	if le := d.authorizeAction(ctx, env.ID, vaultName, scope, st, "get",
		req.Password, req.PresenceToken); le != nil {
		if req.Kind == vault.KindNote {
			return le
		}
		out.NotesWithheld = count > 0
		return mustResponse(env.ID, out)
	}

	var (
		notes []vault.Annotation
		nerr  error
	)
	switch locked := st.IsLocked() && len(req.Password) > 0; {
	case locked && req.IncludeRemoved:
		notes, nerr = st.ListNotesIncludingRemovedWithPassword(ctx, req.Password, ref)
	case locked:
		notes, nerr = st.ListNotesWithPassword(ctx, req.Password, ref)
	case req.IncludeRemoved:
		notes, nerr = st.ListNotesIncludingRemoved(ctx, ref)
	default:
		notes, nerr = st.ListNotes(ctx, ref)
	}
	if nerr != nil {
		if errors.Is(nerr, vault.ErrLocked) {
			if req.Kind == vault.KindNote {
				return mapAnnotationErr(env.ID, nerr)
			}
			out.NotesWithheld = count > 0
			return mustResponse(env.ID, out)
		}
		return mapAnnotationErr(env.ID, nerr)
	}
	for _, n := range notes {
		out.Notes = append(out.Notes, annotationView(n, "vault"))
	}
	resp := mustResponse(env.ID, out)
	d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.read", resp)
	return resp
}

func (d *Daemon) handleAnnotationHistory(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.AnnotationHistoryReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)

	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		return errEnv
	}
	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)

	// History is the record of who changed what. Reading it is a read, gated
	// like one — it can contain every previous version of a private note.
	if le := d.authorizeAction(ctx, env.ID, vaultName, scope, st, "get",
		req.Password, req.PresenceToken); le != nil {
		return le
	}
	ref, err := d.resolveTarget(ctx, st, scope, req.Target)
	if err != nil {
		return mapAnnotationErr(env.ID, err)
	}
	versions, herr := st.AnnotationHistory(ctx, ref, req.ID)
	if herr != nil {
		return mapAnnotationErr(env.ID, herr)
	}
	out := ipc.AnnotationHistoryResp{Versions: make([]ipc.AnnotationVersionView, 0, len(versions))}
	for _, v := range versions {
		out.Versions = append(out.Versions, ipc.AnnotationVersionView{
			VersionNo:  v.VersionNo,
			Op:         v.Op,
			Body:       v.Body,
			Author:     v.Author,
			AuthorComm: v.AuthorComm,
			CreatedAt:  time.Unix(v.CreatedAt, 0),
		})
	}
	resp := mustResponse(env.ID, out)
	d.auditAnnotation(ctx, req.Scope, req.Target, "annotation.history", resp)
	return resp
}

// --- helpers ---

func annotationView(a vault.Annotation, source string) ipc.AnnotationView {
	v := ipc.AnnotationView{
		ID:         a.ID,
		Kind:       a.Kind,
		Body:       a.Body,
		Author:     a.Author,
		AuthorComm: a.AuthorComm,
		Source:     source,
		CreatedAt:  time.Unix(a.CreatedAt, 0),
		UpdatedAt:  time.Unix(a.UpdatedAt, 0),
	}
	if a.DeletedAt != 0 {
		t := time.Unix(a.DeletedAt, 0)
		v.RemovedAt = &t
	}
	return v
}

// auditAnnotation records that an annotation changed — the object, the kind of
// change, and who. Never the text, of either kind.
func (d *Daemon) auditAnnotation(ctx context.Context, scope ipc.Scope, t ipc.AnnotationTarget,
	op string, resp *ipc.Envelope) {

	d.auditPlane(ctx, scope, "annotation", annotationTargetLabel(t), op, resp)
}

func mapAnnotationErr(id string, err error) *ipc.Envelope {
	switch {
	case errors.Is(err, vault.ErrNotAnnotatable):
		return ipc.NewError(id, ipc.CodeBadRequest, err.Error(),
			"name an object byn can annotate: vault, project, env, entry, trust, run or passkey")
	case errors.Is(err, vault.ErrTooManyNotes):
		return ipc.NewError(id, ipc.CodeBadRequest, err.Error(),
			"remove a note before adding another")
	default:
		return mapVaultErr(id, err)
	}
}

func mustResponse(id string, body any) *ipc.Envelope {
	resp, err := ipc.NewResponse(id, body)
	if err != nil {
		return internalErr(id, err)
	}
	return resp
}

// applyPutAnnotations attaches the description and note a put carried.
//
// They apply when the put CREATED the row, or when a person is behind the
// call. They do not apply to an unattended caller overwriting a value it
// authored earlier: that path is free precisely because it discloses nothing,
// and it must not become a way for an agent to reword its own instructions
// after the fact. Whether they were applied is reported back rather than
// silently dropped — a caller that passed a description deserves to know it
// did not take.
func (d *Daemon) applyPutAnnotations(ctx context.Context, st *vault.Store, scope vault.Scope,
	req ipc.PutReq, created, attended bool, authoredKey []byte) bool {

	if req.Description == "" && req.Note == "" {
		return false
	}
	if !created && !attended {
		return false
	}
	ref, err := st.EntryObjectRef(ctx, scope, req.Name)
	if err != nil {
		return false
	}
	author := vault.OwnerAuthor()
	if !attended {
		author = vault.AgentAuthor(callerFrom(ctx).Comm)
	}

	applied := false
	if req.Description != "" {
		if err := st.SetDescription(ctx, ref, req.Description, author); err == nil {
			applied = true
		}
	}
	if req.Note != "" {
		var err error
		switch {
		case len(authoredKey) > 0:
			// The vault may be locked and this caller may hold nothing else.
			// Its note seals under the same key its value did.
			_, err = st.AddNoteAuthored(ctx, ref, req.Note, authoredKey, author)
		case st.IsLocked() && len(req.Password) > 0:
			_, err = st.AddNoteWithPassword(ctx, req.Password, ref, req.Note, author)
		default:
			_, err = st.AddNote(ctx, ref, req.Note, author)
		}
		if err == nil {
			applied = true
		}
	}
	return applied
}

// describeEntry collects every layer of description for one variable: the one
// stored in the vault, then the one a trusted .byn declares. Both are returned
// in that order and never merged — they differ in who vouched for them, and
// flattening them would throw that away.
func (d *Daemon) describeEntry(ctx context.Context, st *vault.Store, scope vault.Scope,
	vaultName, name string) []ipc.DescriptionView {

	var out []ipc.DescriptionView
	if ref, err := st.EntryObjectRef(ctx, scope, name); err == nil {
		if desc, derr := st.GetDescription(ctx, ref); derr == nil {
			out = append(out, ipc.DescriptionView{
				Text:       desc.Body,
				Source:     "vault",
				Author:     desc.Author,
				AuthorComm: desc.AuthorComm,
			})
		}
	}
	if text, ok := d.manifestDescription(vaultName, scope, name); ok {
		out = append(out, ipc.DescriptionView{Text: text, Source: ".byn", Author: vault.AuthorOwner})
	}
	return out
}
