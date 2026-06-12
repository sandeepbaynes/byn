package ipc

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"
)

// DefaultClientTimeout caps a single round-trip on the client side.
// Long-running ops like Init use Argon2 + filesystem fsync; a 60s
// budget is generous.
const DefaultClientTimeout = 60 * time.Second

// ErrDaemonDown is returned by Dial when the daemon socket can't be
// reached (file missing, connection refused, EOF).
var ErrDaemonDown = errors.New("ipc: daemon unreachable")

// Client speaks the daemon protocol over a Unix socket. Each Call
// opens a fresh connection and closes it after a single round-trip;
// this matches the daemon's one-envelope-per-conn server model.
//
// Session, when non-empty, is attached to every outgoing envelope as
// Envelope.Session. Tests and CLI unlock handlers set this field after
// vault.unlock returns a session token so subsequent value-touching ops
// satisfy the NU-3 authorization gate without re-supplying credentials.
type Client struct {
	SocketPath string
	Timeout    time.Duration
	// Session is the active session token. When non-empty it is attached to
	// every Call / CallWithSession envelope so the daemon can validate the
	// caller's live session rather than requiring per-op credentials.
	Session []byte //nolint:gosec // G101: not a static credential
}

// NewClient returns a Client targeting the daemon socket at path.
func NewClient(socketPath string) *Client {
	return &Client{SocketPath: socketPath, Timeout: DefaultClientTimeout}
}

// Call sends op with reqBody and decodes the response into respBody.
// If c.Session is non-empty it is attached to the envelope header so the
// daemon can authorize the caller via the live session.
// Returns *ErrResponse if the daemon replied with an err envelope.
// Returns ErrDaemonDown if the connection couldn't be established.
func (c *Client) Call(op Op, reqBody, respBody any) error {
	return c.CallWithSession(op, reqBody, respBody, c.Session)
}

// CallWithSession sends op with reqBody, attaching session to the envelope
// header (Envelope.Session) so the daemon can validate the caller's active
// session instead of requiring a fresh per-op credential. A nil or empty
// session omits the field (backward-compatible with pre-NU-3 daemons).
// Returns *ErrResponse if the daemon replied with an err envelope.
// Returns ErrDaemonDown if the connection couldn't be established.
func (c *Client) CallWithSession(op Op, reqBody, respBody any, session []byte) error {
	id, err := newID()
	if err != nil {
		return fmt.Errorf("ipc: gen id: %w", err)
	}
	req, err := NewRequest(id, op, reqBody)
	if err != nil {
		return err
	}
	if len(session) > 0 {
		req.Session = session
	}

	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultClientTimeout
	}
	conn, err := net.DialTimeout("unix", c.SocketPath, 2*time.Second)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDaemonDown, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := WriteFrame(conn, req); err != nil {
		return fmt.Errorf("ipc: write: %w", err)
	}
	resp, err := ReadEnvelope(conn)
	if err != nil {
		return fmt.Errorf("ipc: read: %w", err)
	}
	if resp.ID != id {
		return fmt.Errorf("ipc: response id mismatch: got %q, want %q", resp.ID, id)
	}
	if resp.Err != nil {
		return &ErrResponse{Code: resp.Err.Code, Message: resp.Err.Message, Recover: resp.Err.Recover}
	}
	if respBody != nil {
		return DecodeBody(BodyResp, resp, respBody)
	}
	return nil
}

// CallAndCaptureSession sends op with reqBody, attaches session to the
// envelope, decodes the response into respBody, and returns the session
// token from the response envelope header (Envelope.Session). This is
// used for vault.unlock where the caller needs both the response body AND
// the new session token.
func (c *Client) CallAndCaptureSession(op Op, reqBody, respBody any, session []byte) ([]byte, error) {
	id, err := newID()
	if err != nil {
		return nil, fmt.Errorf("ipc: gen id: %w", err)
	}
	req, err := NewRequest(id, op, reqBody)
	if err != nil {
		return nil, err
	}
	if len(session) > 0 {
		req.Session = session
	}

	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultClientTimeout
	}
	conn, err := net.DialTimeout("unix", c.SocketPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDaemonDown, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := WriteFrame(conn, req); err != nil {
		return nil, fmt.Errorf("ipc: write: %w", err)
	}
	resp, err := ReadEnvelope(conn)
	if err != nil {
		return nil, fmt.Errorf("ipc: read: %w", err)
	}
	if resp.ID != id {
		return nil, fmt.Errorf("ipc: response id mismatch: got %q, want %q", resp.ID, id)
	}
	if resp.Err != nil {
		return nil, &ErrResponse{Code: resp.Err.Code, Message: resp.Err.Message, Recover: resp.Err.Recover}
	}
	if respBody != nil {
		if err := DecodeBody(BodyResp, resp, respBody); err != nil {
			return nil, err
		}
	}
	return resp.Session, nil
}

// ErrResponse is the typed error returned when the daemon sends an
// err envelope. The CLI switches on Code to pick exit codes.
type ErrResponse struct {
	Code    ErrCode
	Message string
	Recover string
}

func (e *ErrResponse) Error() string {
	if e.Recover != "" {
		return fmt.Sprintf("%s [%s]; %s", e.Message, e.Code, e.Recover)
	}
	return fmt.Sprintf("%s [%s]", e.Message, e.Code)
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
