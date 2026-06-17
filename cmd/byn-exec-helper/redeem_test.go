package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestRedeemRequested(t *testing.T) {
	if !redeemRequested([]string{"byn-exec-helper", "--redeem"}) {
		t.Error("--redeem not detected")
	}
	if redeemRequested([]string{"byn-exec-helper", "--", "/bin/echo"}) {
		t.Error("legacy `-- TARGET` invocation must NOT be treated as redeem mode")
	}
	if redeemRequested(nil) {
		t.Error("nil args misdetected as redeem")
	}
}

func TestBuildExecArgv(t *testing.T) {
	// No profile → run the target directly.
	got := buildExecArgv("", []string{"/bin/echo", "hi"})
	if len(got) != 2 || got[0] != "/bin/echo" || got[1] != "hi" {
		t.Errorf("no-profile argv = %v, want [/bin/echo hi]", got)
	}
	// With a profile → wrap in `sandbox-exec -p <profile> <argv...>`.
	profile := "(version 1)\n(allow default)"
	got = buildExecArgv(profile, []string{"/bin/echo", "hi"})
	want := []string{sandboxExecPath, "-p", profile, "/bin/echo", "hi"}
	if len(got) != len(want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReadTokenFD(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = w.Write([]byte("my-token"))
		_ = w.Close()
	}()
	tok, err := readTokenFD(r.Fd())
	if err != nil {
		t.Fatalf("readTokenFD: %v", err)
	}
	if string(tok) != "my-token" {
		t.Errorf("token = %q, want my-token", string(tok))
	}
}

// TestRedeemToken drives redeemToken against an in-process daemon stub that
// answers exec.redeem, verifying the token is sent and the argv/env/profile are
// returned.
func TestRedeemToken(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "byn-helper-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	gotToken := make(chan []byte, 1)
	go func() {
		conn, aerr := l.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		env, rerr := ipc.ReadEnvelope(conn)
		if rerr != nil {
			return
		}
		var req ipc.ExecRedeemReq
		_ = ipc.DecodeBody(ipc.BodyReq, env, &req)
		gotToken <- req.Token
		resp, _ := ipc.NewResponse(env.ID, ipc.ExecRedeemResp{
			Argv:           []string{"/bin/echo", "hi"},
			Env:            []string{"PATH=/usr/bin"},
			SandboxProfile: "prof",
		})
		_ = ipc.WriteFrame(conn, resp)
	}()

	argv, env, profile, err := redeemToken(sock, []byte("tok-xyz"))
	if err != nil {
		t.Fatalf("redeemToken: %v", err)
	}
	if got := string(<-gotToken); got != "tok-xyz" {
		t.Errorf("daemon received token %q, want tok-xyz", got)
	}
	if len(argv) != 2 || argv[0] != "/bin/echo" {
		t.Errorf("argv = %v, want [/bin/echo hi]", argv)
	}
	if len(env) != 1 || env[0] != "PATH=/usr/bin" {
		t.Errorf("env = %v, want [PATH=/usr/bin]", env)
	}
	if profile != "prof" {
		t.Errorf("profile = %q, want prof", profile)
	}
}
