package ipc

import (
	"bytes"
	"errors"
	"testing"
)

func TestReadEnvelope_BadVersion(t *testing.T) {
	var buf bytes.Buffer
	type rawV struct {
		V  uint   `json:"v"`
		ID string `json:"id"`
	}
	if err := WriteFrame(&buf, rawV{V: 999, ID: "x"}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	_, err := ReadEnvelope(&buf)
	if err == nil || !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("err = %v", err)
	}
}

func TestReadEnvelope_OK(t *testing.T) {
	var buf bytes.Buffer
	req, _ := NewRequest("id1", OpStatus, StatusReq{})
	if err := WriteFrame(&buf, req); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	env, err := ReadEnvelope(&buf)
	if err != nil {
		t.Fatalf("ReadEnvelope: %v", err)
	}
	if env.ID != "id1" || env.Op != OpStatus {
		t.Fatalf("env=%+v", env)
	}
}

func TestDecodeBody_EmptyBody(t *testing.T) {
	env := &Envelope{V: ProtocolVersion, ID: "x"}
	var out StatusReq
	if err := DecodeBody(BodyReq, env, &out); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestDecodeBody_RoundTrip(t *testing.T) {
	req, _ := NewRequest("id1", OpVaultUnlock, VaultUnlockReq{Name: "v", Password: []byte("pw")})
	var got VaultUnlockReq
	if err := DecodeBody(BodyReq, req, &got); err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.Name != "v" || string(got.Password) != "pw" {
		t.Fatalf("got %+v", got)
	}
}

func TestDecodeBody_RespSide(t *testing.T) {
	resp, _ := NewResponse("id1", StatusResp{Version: "x"})
	var got StatusResp
	if err := DecodeBody(BodyResp, resp, &got); err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.Version != "x" {
		t.Fatalf("got %+v", got)
	}
}

func TestDecodeBody_BadJSON(t *testing.T) {
	env := &Envelope{V: ProtocolVersion, Req: []byte("not json")}
	var out StatusReq
	if err := DecodeBody(BodyReq, env, &out); err == nil {
		t.Fatal("expected decode err")
	}
}

func TestNewRequest_NilBody(t *testing.T) {
	// nil body marshals to "null" which is fine.
	req, err := NewRequest("id1", OpStatus, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if req.ID != "id1" {
		t.Fatalf("ID=%q", req.ID)
	}
}

func TestNewError_Populates(t *testing.T) {
	e := NewError("id1", CodeNotFound, "no", "create")
	if e.Err == nil || e.Err.Code != CodeNotFound {
		t.Fatalf("err = %+v", e.Err)
	}
}
