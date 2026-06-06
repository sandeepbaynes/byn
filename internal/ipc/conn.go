package ipc

import (
	"encoding/json"
	"fmt"
	"io"
)

// ReadEnvelope reads one Envelope from r. Use for the initial
// envelope parse; then unmarshal Req or Resp via DecodeBody.
func ReadEnvelope(r io.Reader) (*Envelope, error) {
	var env Envelope
	if err := ReadFrame(r, &env); err != nil {
		return nil, err
	}
	if env.V == 0 {
		return nil, fmt.Errorf("ipc: missing v field")
	}
	if env.V != ProtocolVersion {
		return &env, fmt.Errorf("%w: peer v=%d, this build v=%d", ErrUnsupportedVersion, env.V, ProtocolVersion)
	}
	return &env, nil
}

// ErrUnsupportedVersion is returned by ReadEnvelope when the peer
// sends a version this build doesn't understand. The returned
// Envelope is non-nil so the caller can still echo the ID in the
// error response.
var ErrUnsupportedVersion = fmt.Errorf("ipc: unsupported protocol version")

// DecodeBody unmarshals env.Req (request side) or env.Resp (response
// side) into v. Pass which side via the from param.
func DecodeBody(from BodySide, env *Envelope, v any) error {
	var raw []byte
	switch from {
	case BodyReq:
		raw = env.Req
	case BodyResp:
		raw = env.Resp
	}
	if len(raw) == 0 {
		// Empty body is valid for empty op types (e.g. LockReq{}).
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("ipc: decode body: %w", err)
	}
	return nil
}

// BodySide selects which side of an Envelope to decode.
type BodySide int

// BodyReq/BodyResp pick the request or response body.
const (
	BodyReq BodySide = iota
	BodyResp
)

// NewRequest builds a request envelope with op-specific body.
func NewRequest(id string, op Op, body any) (*Envelope, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("ipc: encode req: %w", err)
	}
	return &Envelope{
		V:   ProtocolVersion,
		ID:  id,
		Op:  op,
		Req: raw,
	}, nil
}

// NewResponse builds a response envelope with op-specific body.
func NewResponse(id string, body any) (*Envelope, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("ipc: encode resp: %w", err)
	}
	return &Envelope{
		V:    ProtocolVersion,
		ID:   id,
		Resp: raw,
	}, nil
}

// NewError builds an error envelope.
func NewError(id string, code ErrCode, message, recoverHint string) *Envelope {
	return &Envelope{
		V:  ProtocolVersion,
		ID: id,
		Err: &ErrMsg{
			Code:    code,
			Message: message,
			Recover: recoverHint,
		},
	}
}
