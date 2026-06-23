// Data layer: IPC client wrappers exposed as tea.Cmds.
//
// All daemon calls run as commands so the UI thread never blocks. Each
// command returns a tea.Msg containing the result, which Update folds
// into the model.
package tui

import (
	"time"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// Client is the IPC surface the TUI needs. Implemented by
// *ipc.Client; defined as an interface so tests can fake.
type Client interface {
	Call(op ipc.Op, req any, resp any) error
}

// clipboardWrite is the indirect for clipboard.WriteAll so tests can
// inject a fake (the system clipboard isn't usable in CI).
var clipboardWrite = clipboard.WriteAll

// ---- Messages returned by the commands ----------------------------------

type statusLoadedMsg struct {
	Resp ipc.StatusResp
	Err  error
}

type projectsLoadedMsg struct {
	Vault string
	Resp  ipc.ProjectListResp
	Err   error
}

type envsLoadedMsg struct {
	Vault, Project string
	Resp           ipc.EnvListResp
	Err            error
}

type entriesLoadedMsg struct {
	Scope ipc.Scope
	Resp  ipc.ListResp
	Err   error
}

// defaultEnvLoadedMsg carries the entry list of the default env for a
// given (vault, project). Used by the renderer to mark inherited /
// overridden / new entries in non-default envs.
type defaultEnvLoadedMsg struct {
	Vault, Project string
	Resp           ipc.ListResp
	Err            error
}

type entryValueMsg struct {
	Scope ipc.Scope
	Name  string
	Resp  ipc.GetResp
	Err   error
}

type opCompleteMsg struct {
	Op   string
	Err  error
	Note string
	// authCtx is the auth-retry context captured at dispatch time.
	// Carrying it in the message (rather than storing on the model at
	// dispatch time) prevents a second op dispatched before the first
	// result lands from overwriting the pending context.
	authCtx *authReqState
}

type auditLoadedMsg struct {
	Vault string
	Resp  ipc.AuditTailResp
	Err   error
}

type tickMsg time.Time

// ---- Commands -----------------------------------------------------------

func loadStatusCmd(c Client) tea.Cmd {
	return func() tea.Msg {
		var resp ipc.StatusResp
		err := c.Call(ipc.OpStatus, ipc.StatusReq{}, &resp)
		return statusLoadedMsg{Resp: resp, Err: err}
	}
}

func loadProjectsCmd(c Client, vault string) tea.Cmd {
	return func() tea.Msg {
		var resp ipc.ProjectListResp
		err := c.Call(ipc.OpProjectList, ipc.ProjectListReq{Vault: vault}, &resp)
		return projectsLoadedMsg{Vault: vault, Resp: resp, Err: err}
	}
}

func loadEnvsCmd(c Client, vault, project string) tea.Cmd {
	return func() tea.Msg {
		var resp ipc.EnvListResp
		err := c.Call(ipc.OpEnvList, ipc.EnvListReq{Vault: vault, Project: project}, &resp)
		return envsLoadedMsg{Vault: vault, Project: project, Resp: resp, Err: err}
	}
}

func loadEntriesCmd(c Client, scope ipc.Scope) tea.Cmd {
	return func() tea.Msg {
		var resp ipc.ListResp
		err := c.Call(ipc.OpList, ipc.ListReq{Scope: scope}, &resp)
		return entriesLoadedMsg{Scope: scope, Resp: resp, Err: err}
	}
}

// loadDefaultEnvNamesCmd lists the entries that physically live in
// the default env of (vault, project). Only the names are used; the
// values stay encrypted in the daemon.
func loadDefaultEnvNamesCmd(c Client, vault, project string) tea.Cmd {
	return func() tea.Msg {
		var resp ipc.ListResp
		err := c.Call(ipc.OpList,
			ipc.ListReq{Scope: ipc.Scope{Vault: vault, Project: project, Env: "default"}},
			&resp)
		return defaultEnvLoadedMsg{Vault: vault, Project: project, Resp: resp, Err: err}
	}
}

func getValueCmd(c Client, scope ipc.Scope, name string) tea.Cmd {
	return func() tea.Msg {
		var resp ipc.GetResp
		err := c.Call(ipc.OpGet, ipc.GetReq{Scope: scope, Name: name}, &resp)
		return entryValueMsg{Scope: scope, Name: name, Resp: resp, Err: err}
	}
}

// clipboardYankedMsg signals that a yank attempt completed.
type clipboardYankedMsg struct {
	Name  string
	Bytes int
	Err   error
}

// yankToClipboardCmd fetches an entry's value from the daemon and
// writes it to the system clipboard in one step. Triggers a daemon
// audit event (the get is recorded in the HMAC chain just like a
// reveal).
func yankToClipboardCmd(c Client, scope ipc.Scope, name string) tea.Cmd {
	return func() tea.Msg {
		var resp ipc.GetResp
		if err := c.Call(ipc.OpGet, ipc.GetReq{Scope: scope, Name: name}, &resp); err != nil {
			return clipboardYankedMsg{Name: name, Err: err}
		}
		if err := clipboardWrite(string(resp.Value)); err != nil {
			return clipboardYankedMsg{Name: name, Err: err}
		}
		return clipboardYankedMsg{Name: name, Bytes: len(resp.Value)}
	}
}

func putValueCmd(c Client, scope ipc.Scope, name string, value []byte, ctx *authReqState) tea.Cmd {
	return func() tea.Msg {
		err := c.Call(ipc.OpPut, ipc.PutReq{Scope: scope, Name: name, Value: value}, &ipc.PutResp{})
		return opCompleteMsg{Op: "put", Err: err, Note: name, authCtx: ctx}
	}
}

// addEntryCmd wraps OpPut with CreateOnly=true so the daemon refuses
// a duplicate name. Used by ADD-ENTRY commit to surface duplicates
// even when the local pre-check missed (race with another writer).
func addEntryCmd(c Client, scope ipc.Scope, name string, value []byte, ctx *authReqState) tea.Cmd {
	return func() tea.Msg {
		err := c.Call(ipc.OpPut,
			ipc.PutReq{Scope: scope, Name: name, Value: value, CreateOnly: true},
			&ipc.PutResp{})
		return opCompleteMsg{Op: "add", Err: err, Note: name, authCtx: ctx}
	}
}

func deleteEntryCmd(c Client, scope ipc.Scope, name string, ctx *authReqState) tea.Cmd {
	return func() tea.Msg {
		err := c.Call(ipc.OpDelete, ipc.DeleteReq{Scope: scope, Name: name}, &ipc.DeleteResp{})
		return opCompleteMsg{Op: "delete", Err: err, Note: name, authCtx: ctx}
	}
}

func renameEntryCmd(c Client, scope ipc.Scope, oldName, newName string, ctx *authReqState) tea.Cmd {
	return func() tea.Msg {
		err := c.Call(ipc.OpRename,
			ipc.RenameReq{Scope: scope, OldName: oldName, NewName: newName},
			&ipc.RenameResp{})
		return opCompleteMsg{Op: "rename", Err: err, Note: newName, authCtx: ctx}
	}
}

// scopeRenamedMsg reports the result of a rail-node (vault/project/env)
// rename, carrying enough context to patch the tree's expanded/scope state.
type scopeRenamedMsg struct {
	Kind           railNodeKind
	Vault, Project string
	Old, New       string
	Err            error
}

// scopeRenameCmd renames a rail node — a vault, project, or env — via the
// matching IPC op.
func scopeRenameCmd(c Client, kind railNodeKind, vlt, project, oldName, newName string) tea.Cmd {
	return func() tea.Msg {
		var err error
		switch kind {
		case nodeVault:
			err = c.Call(ipc.OpVaultRename,
				ipc.VaultRenameReq{OldName: oldName, NewName: newName}, &ipc.VaultRenameResp{})
		case nodeProject:
			err = c.Call(ipc.OpProjectRename,
				ipc.ProjectRenameReq{Vault: vlt, OldName: oldName, NewName: newName}, &ipc.ProjectRenameResp{})
		case nodeEnv:
			err = c.Call(ipc.OpEnvRename,
				ipc.EnvRenameReq{Vault: vlt, Project: project, OldName: oldName, NewName: newName}, &ipc.EnvRenameResp{})
		}
		return scopeRenamedMsg{Kind: kind, Vault: vlt, Project: project, Old: oldName, New: newName, Err: err}
	}
}

// scopeChangedMsg reports a rail-node create/delete that requires a full
// tree reload (statusLoadedMsg cascades to projects/envs).
type scopeChangedMsg struct {
	Note string
	Err  error
}

// scopeDeleteCmd deletes a rail node — vault, project, or env — via the
// matching IPC op. The vault must be unlocked (the TUI gates on that).
func scopeDeleteCmd(c Client, kind railNodeKind, vlt, project, name string) tea.Cmd {
	return func() tea.Msg {
		var err error
		switch kind {
		case nodeVault:
			err = c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: name}, &ipc.VaultDeleteResp{})
		case nodeProject:
			err = c.Call(ipc.OpProjectDelete, ipc.ProjectDeleteReq{Vault: vlt, Name: name}, &ipc.ProjectDeleteResp{})
		case nodeEnv:
			err = c.Call(ipc.OpEnvDelete, ipc.EnvDeleteReq{Vault: vlt, Project: project, Name: name}, &ipc.EnvDeleteResp{})
		}
		return scopeChangedMsg{Note: "deleted " + name, Err: err}
	}
}

func loadAuditCmd(c Client, vault string, lines int) tea.Cmd {
	return loadAuditPageCmd(c, vault, lines, 0)
}

// loadAuditPageCmd loads one page; before>0 fetches the page of events with chain
// index (#N) below before — a stable cursor for paging back through a growing log.
func loadAuditPageCmd(c Client, vault string, lines, before int) tea.Cmd {
	return func() tea.Msg {
		var resp ipc.AuditTailResp
		err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Vault: vault, Lines: lines, Before: before}, &resp)
		return auditLoadedMsg{Vault: vault, Resp: resp, Err: err}
	}
}

// tickCmd schedules a tick after d. Used by REVEAL countdown and the
// generic refresh loop.
func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// ---- Auth step-up retry commands ----------------------------------------
//
// These are exact copies of the value-op commands above, but with the
// Password field set. They share the same result message types so the
// Update handler can fold them identically.
//
// Each function zeros pw after c.Call returns.
// Note: buffer zeroed; JSON marshaling copies are subject to GC.

// authRetryMsg carries the result of retrying an op after the user
// supplied a password in the "Authorize" overlay.
type authRetryMsg struct {
	// kind identifies which op was retried so Update can apply the
	// right success path (reveal prefill vs. entry reload).
	kind    authRetryKind
	name    string // entry name, for entryValueMsg / opCompleteMsg routing
	getResp ipc.GetResp
	err     error
}

// authRetryKind mirrors authPendingOpKind but lives in the data layer.
type authRetryKind int

const (
	authRetryGet authRetryKind = iota
	authRetryPut
	authRetryDelete
	authRetryRename
)

// authRetryGetCmd re-issues OpGet with the supplied password.
// pw is zeroed after the call returns; a copy is passed to the request so
// the struct is independent of the zeroing.
// Note: buffer zeroed; JSON marshaling copies are subject to GC.
func authRetryGetCmd(c Client, scope ipc.Scope, name string, pw []byte) tea.Cmd {
	return func() tea.Msg {
		var resp ipc.GetResp
		pwCopy := append([]byte{}, pw...) //nolint:gocritic // deliberate copy before zeroing pw
		err := c.Call(ipc.OpGet, ipc.GetReq{Scope: scope, Name: name, Password: pwCopy}, &resp)
		for i := range pw {
			pw[i] = 0
		}
		return authRetryMsg{kind: authRetryGet, name: name, getResp: resp, err: err}
	}
}

// authRetryPutCmd re-issues OpPut with the supplied password.
// Note: buffer zeroed; JSON marshaling copies are subject to GC.
func authRetryPutCmd(c Client, scope ipc.Scope, name string, value []byte, pw []byte) tea.Cmd {
	return func() tea.Msg {
		pwCopy := append([]byte{}, pw...) //nolint:gocritic
		err := c.Call(ipc.OpPut, ipc.PutReq{Scope: scope, Name: name, Value: value, Password: pwCopy}, &ipc.PutResp{})
		for i := range pw {
			pw[i] = 0
		}
		return authRetryMsg{kind: authRetryPut, name: name, err: err}
	}
}

// authRetryAddCmd re-issues OpPut with CreateOnly and the supplied password.
// Note: buffer zeroed; JSON marshaling copies are subject to GC.
func authRetryAddCmd(c Client, scope ipc.Scope, name string, value []byte, pw []byte) tea.Cmd {
	return func() tea.Msg {
		pwCopy := append([]byte{}, pw...) //nolint:gocritic
		err := c.Call(ipc.OpPut, ipc.PutReq{Scope: scope, Name: name, Value: value, CreateOnly: true, Password: pwCopy}, &ipc.PutResp{})
		for i := range pw {
			pw[i] = 0
		}
		return authRetryMsg{kind: authRetryPut, name: name, err: err}
	}
}

// authRetryDeleteCmd re-issues OpDelete with the supplied password.
// Note: buffer zeroed; JSON marshaling copies are subject to GC.
func authRetryDeleteCmd(c Client, scope ipc.Scope, name string, pw []byte) tea.Cmd {
	return func() tea.Msg {
		pwCopy := append([]byte{}, pw...) //nolint:gocritic
		err := c.Call(ipc.OpDelete, ipc.DeleteReq{Scope: scope, Name: name, Password: pwCopy}, &ipc.DeleteResp{})
		for i := range pw {
			pw[i] = 0
		}
		return authRetryMsg{kind: authRetryDelete, name: name, err: err}
	}
}

// authRetryRenameCmd re-issues OpRename with the supplied password.
// Note: buffer zeroed; JSON marshaling copies are subject to GC.
func authRetryRenameCmd(c Client, scope ipc.Scope, oldName, newName string, pw []byte) tea.Cmd {
	return func() tea.Msg {
		pwCopy := append([]byte{}, pw...) //nolint:gocritic
		err := c.Call(ipc.OpRename, ipc.RenameReq{Scope: scope, OldName: oldName, NewName: newName, Password: pwCopy}, &ipc.RenameResp{})
		for i := range pw {
			pw[i] = 0
		}
		return authRetryMsg{kind: authRetryRename, name: newName, err: err}
	}
}
