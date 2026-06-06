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
type Client struct {
	SocketPath string
	Timeout    time.Duration
}

// NewClient returns a Client targeting the daemon socket at path.
func NewClient(socketPath string) *Client {
	return &Client{SocketPath: socketPath, Timeout: DefaultClientTimeout}
}

// Call sends op with reqBody and decodes the response into respBody.
// Returns *ErrResponse if the daemon replied with an err envelope.
// Returns ErrDaemonDown if the connection couldn't be established.
func (c *Client) Call(op Op, reqBody, respBody any) error {
	id, err := newID()
	if err != nil {
		return fmt.Errorf("ipc: gen id: %w", err)
	}
	req, err := NewRequest(id, op, reqBody)
	if err != nil {
		return err
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
