package ipc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

type stub struct {
	V    uint   `json:"v"`
	Name string `json:"name,omitempty"`
}

func TestReadWriteFrame_Roundtrip(t *testing.T) {
	var buf bytes.Buffer
	in := stub{V: 1, Name: "hello"}
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	var out stub
	if err := ReadFrame(&buf, &out); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if out != in {
		t.Fatalf("mismatch: got %+v, want %+v", out, in)
	}
}

func TestReadFrame_TruncatedHeader(t *testing.T) {
	r := bytes.NewReader([]byte{0, 0})
	var out stub
	if err := ReadFrame(r, &out); !errors.Is(err, ErrShortFrame) && !errors.Is(err, io.EOF) {
		t.Fatalf("truncated header: err = %v, want ShortFrame/EOF", err)
	}
}

func TestReadFrame_ZeroLength(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))
	var out stub
	if err := ReadFrame(&buf, &out); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("zero length: err = %v, want ShortFrame", err)
	}
}

func TestReadFrame_TruncatedBody(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(10))
	buf.Write([]byte("ab"))
	var out stub
	if err := ReadFrame(&buf, &out); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("truncated body: err = %v, want ShortFrame", err)
	}
}

func TestReadFrame_Oversized(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, MaxFrameSize+1)
	var out stub
	if err := ReadFrame(&buf, &out); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized: err = %v, want ErrFrameTooLarge", err)
	}
}

func TestReadFrame_UnknownField(t *testing.T) {
	var buf bytes.Buffer
	body := []byte(`{"v":1,"name":"x","extra":1}`)
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(body)))
	buf.Write(body)
	var out stub
	err := ReadFrame(&buf, &out)
	if err == nil || !strings.Contains(err.Error(), "extra") && !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field: err = %v, want decode error mentioning the field", err)
	}
}

func TestWriteFrame_Oversized(t *testing.T) {
	big := strings.Repeat("a", int(MaxFrameSize))
	v := stub{V: 1, Name: big}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, v); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized write: err = %v, want ErrFrameTooLarge", err)
	}
}

func TestReadEnvelope_VersionMismatch(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, &Envelope{V: 999, ID: "x"}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	env, err := ReadEnvelope(&buf)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("ReadEnvelope version mismatch: err = %v, want ErrUnsupportedVersion", err)
	}
	if env == nil || env.ID != "x" {
		t.Fatalf("ReadEnvelope returned nil/wrong env on version mismatch; want env.ID=x")
	}
}

func TestReadEnvelope_MissingVersion(t *testing.T) {
	var buf bytes.Buffer
	body := []byte(`{"id":"x"}`)
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(body)))
	buf.Write(body)
	if _, err := ReadEnvelope(&buf); err == nil {
		t.Fatal("missing v: want error")
	}
}

func TestNewRequest_DecodeBody_Roundtrip(t *testing.T) {
	req := PutReq{Name: "k", Value: []byte("v"), CreateOnly: true}
	env, err := NewRequest("id-1", OpPut, req)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, env); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadEnvelope(&buf)
	if err != nil {
		t.Fatalf("ReadEnvelope: %v", err)
	}
	if got.Op != OpPut || got.ID != "id-1" {
		t.Fatalf("envelope mismatch: %+v", got)
	}
	var body PutReq
	if err := DecodeBody(BodyReq, got, &body); err != nil {
		t.Fatalf("DecodeBody: %v", err)
	}
	if body.Name != req.Name || !bytes.Equal(body.Value, req.Value) || body.CreateOnly != req.CreateOnly {
		t.Fatalf("body mismatch: got %+v, want %+v", body, req)
	}
}

func TestNewResponse_DecodeBody_Roundtrip(t *testing.T) {
	resp := GetResp{Name: "k", Value: []byte("v")}
	env, err := NewResponse("id-2", resp)
	if err != nil {
		t.Fatalf("NewResponse: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, env); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadEnvelope(&buf)
	if err != nil {
		t.Fatalf("ReadEnvelope: %v", err)
	}
	var body GetResp
	if err := DecodeBody(BodyResp, got, &body); err != nil {
		t.Fatalf("DecodeBody: %v", err)
	}
	if body.Name != resp.Name || !bytes.Equal(body.Value, resp.Value) {
		t.Fatalf("body mismatch: got %+v, want %+v", body, resp)
	}
}

func TestNewError_ShapeOnWire(t *testing.T) {
	env := NewError("id-3", CodeWrongPassword, "bad password", "retry: byn unlock")
	var buf bytes.Buffer
	if err := WriteFrame(&buf, env); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadEnvelope(&buf)
	if err != nil {
		t.Fatalf("ReadEnvelope: %v", err)
	}
	if got.Err == nil {
		t.Fatal("err missing")
	}
	if got.Err.Code != CodeWrongPassword {
		t.Fatalf("code = %s, want %s", got.Err.Code, CodeWrongPassword)
	}
	if got.Err.Message != "bad password" || got.Err.Recover != "retry: byn unlock" {
		t.Fatalf("err mismatch: %+v", got.Err)
	}
}

func TestDecodeBody_EmptyBodyOK(t *testing.T) {
	env, err := NewRequest("id-4", OpVaultLock, VaultLockReq{})
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	var body VaultLockReq
	if err := DecodeBody(BodyReq, env, &body); err != nil {
		t.Fatalf("DecodeBody empty: %v", err)
	}
}
