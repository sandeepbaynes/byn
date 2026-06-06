package ipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxFrameSize is the upper bound on a single JSON-encoded message.
// 1 MiB is well above any real secret, and rejecting larger frames
// defends against memory exhaustion via a malicious or buggy peer.
const MaxFrameSize uint32 = 1 << 20

// LengthPrefixSize is the size of the 4-byte big-endian length prefix.
const LengthPrefixSize = 4

// Errors returned by frame reads/writes.
var (
	// ErrFrameTooLarge is returned when the length prefix exceeds
	// MaxFrameSize.
	ErrFrameTooLarge = errors.New("ipc: frame exceeds max size")

	// ErrShortFrame is returned when the connection ends mid-frame.
	ErrShortFrame = errors.New("ipc: short frame")
)

// ReadFrame reads one JSON-encoded message from r into v. v must be a
// non-nil pointer. The frame is decoded with strict json (extra
// fields rejected).
func ReadFrame(r io.Reader, v any) error {
	var hdr [LengthPrefixSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrShortFrame
		}
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return ErrShortFrame
	}
	if n > MaxFrameSize {
		// Drain the reader to keep the stream usable would be ideal,
		// but the safe move is to fail and let the caller close the
		// connection. A peer sending >1 MiB is misbehaving.
		return fmt.Errorf("%w: %d", ErrFrameTooLarge, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrShortFrame
		}
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("ipc: decode: %w", err)
	}
	return nil
}

// WriteFrame encodes v as JSON and writes a single length-prefixed
// frame to w. The full frame is written via a single Write call when
// possible to keep small-frame latency low.
func WriteFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("ipc: encode: %w", err)
	}
	if uint64(len(body)) > uint64(MaxFrameSize) {
		return fmt.Errorf("%w: encoded %d bytes", ErrFrameTooLarge, len(body))
	}
	frame := make([]byte, LengthPrefixSize+len(body))
	binary.BigEndian.PutUint32(frame[:LengthPrefixSize], uint32(len(body))) //nolint:gosec // bounded by MaxFrameSize check above
	copy(frame[LengthPrefixSize:], body)
	if _, err := w.Write(frame); err != nil {
		return err
	}
	return nil
}
