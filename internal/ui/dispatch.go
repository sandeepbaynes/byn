package ui

import (
	"context"
	"net/http"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// Dispatcher is the slice of the daemon the UI needs: route one IPC
// envelope in-process and return the response. The daemon satisfies it,
// so every web request goes through the exact same business logic (scope
// resolution, audit, lock checks, inheritance) as the CLI and TUI.
type Dispatcher interface {
	Dispatch(ctx context.Context, env *ipc.Envelope) *ipc.Envelope
}

// uiRequestID labels in-process envelopes. Correlation isn't needed for a
// synchronous call/response, so a constant is fine.
const uiRequestID = "ui"

// call dispatches op in-process and decodes the response body into
// respBody (may be nil). It returns the daemon's typed error (nil if the
// op succeeded) separately from a transport/decode error.
func (s *Server) call(ctx context.Context, op ipc.Op, reqBody, respBody any) (*ipc.ErrMsg, error) {
	ipcErr, _, err := s.callCapture(ctx, nil, op, reqBody, respBody)
	return ipcErr, err
}

// callInVault is like call but looks up and attaches the stored session
// token for vaultName (if any) before dispatching, and stores any
// session token the daemon returns.  Use this from every handler that
// knows its vault so that a portal-unlock or passkey-auth-finish session
// is automatically threaded into subsequent value-touching ops.
//
// Token lifecycle:
//   - Portal holds tokens in memory only — never localStorage, never disk.
//   - A page reload clears the JS state; the Go server's in-memory map
//     survives until the daemon restarts.  The daemon validates the token
//     on every call, so a stale in-memory token is rejected and the
//     caller sees CodeAuthRequired (the portal's apiWithAuth handles
//     that transparently).
func (s *Server) callInVault(ctx context.Context, vaultName string, op ipc.Op, reqBody, respBody any) (*ipc.ErrMsg, error) {
	tok := s.loadVaultSession(vaultName)
	ipcErr, returned, err := s.callCapture(ctx, tok, op, reqBody, respBody)
	if err != nil {
		return nil, err
	}
	// Store any newly issued token (e.g. re-mint on passkey auth).
	if len(returned) > 0 {
		s.storeVaultSession(vaultName, returned)
	}
	// Dead-entry hygiene: if the daemon rejected our stored token with
	// CodeAuthRequired (e.g. after daemon restart), remove the stale
	// entry so the next call does not re-present a dead token.
	if ipcErr != nil && ipcErr.Code == ipc.CodeAuthRequired && len(tok) > 0 {
		s.clearVaultSession(vaultName)
	}
	return ipcErr, nil
}

// callCapture is the low-level dispatcher: it builds the request
// envelope, sets session (may be nil), dispatches, and returns the
// daemon error, any returned session token, and a transport/decode error.
func (s *Server) callCapture(ctx context.Context, session []byte, op ipc.Op, reqBody, respBody any) (*ipc.ErrMsg, []byte, error) {
	req, err := ipc.NewRequest(uiRequestID, op, reqBody)
	if err != nil {
		return nil, nil, err
	}
	if len(session) > 0 {
		req.Session = session
	}
	resp := s.disp.Dispatch(ctx, req)
	if resp.Err != nil {
		return resp.Err, nil, nil
	}
	if respBody != nil {
		if err := ipc.DecodeBody(ipc.BodyResp, resp, respBody); err != nil {
			return nil, nil, err
		}
	}
	return nil, resp.Session, nil
}

// httpStatusForCode maps a daemon error code to an HTTP status so the
// browser can react (re-unlock on 423/401, show conflicts, etc.).
func httpStatusForCode(code ipc.ErrCode) int {
	switch code {
	case ipc.CodeLocked:
		return http.StatusLocked // 423 — vault locked, re-unlock
	case ipc.CodeAuthRequired:
		return http.StatusUnauthorized // 401 — per_action_auth gate: supply password/presence_token
	case ipc.CodeWrongPassword:
		return http.StatusUnauthorized
	case ipc.CodeRateLimited:
		return http.StatusTooManyRequests
	case ipc.CodeNotFound, ipc.CodeVaultNotFound, ipc.CodeProjectNotFound,
		ipc.CodeEnvNotFound, ipc.CodeNotInit:
		return http.StatusNotFound
	case ipc.CodeAlreadyExists, ipc.CodeVaultExists, ipc.CodeProjectExists,
		ipc.CodeEnvExists, ipc.CodeAlreadyInit:
		return http.StatusConflict
	case ipc.CodeBadName, ipc.CodeBadRequest, ipc.CodeUnknownOp,
		ipc.CodeEnvProtected, ipc.CodeFingerprint:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
