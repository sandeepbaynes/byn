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
	req, err := ipc.NewRequest(uiRequestID, op, reqBody)
	if err != nil {
		return nil, err
	}
	resp := s.disp.Dispatch(ctx, req)
	if resp.Err != nil {
		return resp.Err, nil
	}
	if respBody != nil {
		if err := ipc.DecodeBody(ipc.BodyResp, resp, respBody); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// httpStatusForCode maps a daemon error code to an HTTP status so the
// browser can react (re-unlock on 423/401, show conflicts, etc.).
func httpStatusForCode(code ipc.ErrCode) int {
	switch code {
	case ipc.CodeLocked:
		return http.StatusLocked // 423 — vault locked, re-unlock
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
