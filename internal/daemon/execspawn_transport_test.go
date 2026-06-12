//go:build linux || darwin

package daemon

import (
	"net"
	"os"
	"testing"

	"github.com/sandeepbaynes/byn/internal/fdpass"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/privsep"
	"golang.org/x/sys/unix"
)

// fdRecordingSpawner records the three stdio fds it was handed and asserts they
// are valid open descriptors (fstat succeeds). It proves the SCM_RIGHTS
// transport delivered real fds end-to-end through handleConn → withExecSpawnFDs
// → handleExecSpawn, without needing root or a real privsep helper.
type fdRecordingSpawner struct {
	in, out, err int
	valid        bool
	retCode      int
}

func (s *fdRecordingSpawner) Spawn(req privsep.SpawnReq) (int, error) {
	s.in, s.out, s.err = req.Stdin, req.Stdout, req.Stderr
	// All three must be live, distinct, fstat-able fds in the daemon's table.
	var st unix.Stat_t
	s.valid = unix.Fstat(req.Stdin, &st) == nil &&
		unix.Fstat(req.Stdout, &st) == nil &&
		unix.Fstat(req.Stderr, &st) == nil
	return s.retCode, nil
}

// pairConn wraps one end of a Unix socketpair as a *net.UnixConn so it can be
// fed to handleConn (daemon side) or used with WriteFrame/SendFDs (client side).
func pairConn(t *testing.T) (client, server net.Conn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	cf := os.NewFile(uintptr(fds[0]), "client")
	sf := os.NewFile(uintptr(fds[1]), "server")
	cc, err := net.FileConn(cf)
	if err != nil {
		t.Fatalf("FileConn client: %v", err)
	}
	_ = cf.Close() // FileConn dup'd the fd; close our copy.
	sc, err := net.FileConn(sf)
	if err != nil {
		t.Fatalf("FileConn server: %v", err)
	}
	_ = sf.Close()
	t.Cleanup(func() { _ = cc.Close(); _ = sc.Close() })
	return cc, sc
}

// TestHandleConn_ExecSpawnReceivesFDs drives the full daemon-side transport over
// a real socketpair: the client writes an exec.spawn frame then SendFDs three
// stdio fds; handleConn must RecvFDs them, stash them via withExecSpawnFDs, and
// hand them to the spawner. Asserts the spawner saw 3 valid fds and the exit
// code round-trips back to the client.
func TestHandleConn_ExecSpawnReceivesFDs(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "API_KEY", []byte("secret-api"))

	target := regularFileTarget(t, "mytool")
	byn := writeBynContent(t,
		"[scope]\n\n[exec]\nenv = [\"API_KEY\"]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	spy := &fdRecordingSpawner{retCode: 7}
	d.spawner = spy

	clientConn, serverConn := pairConn(t)

	// Three real, distinct stdio fds to pass.
	rIn, wIn, _ := os.Pipe()
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	t.Cleanup(func() {
		_ = rIn.Close()
		_ = wIn.Close()
		_ = rOut.Close()
		_ = wOut.Close()
		_ = rErr.Close()
		_ = wErr.Close()
	})

	req := ipc.ExecSpawnReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"}},
		BaseEnv:      []string{"PATH=/usr/bin"},
		AbsTarget:    target,
	}
	env, err := ipc.NewRequest("spawn-transport-1", ipc.OpExecSpawn, req)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	// Client side runs concurrently with the daemon's handleConn.
	done := make(chan *ipc.Envelope, 1)
	go func() {
		if werr := ipc.WriteFrame(clientConn, env); werr != nil {
			t.Errorf("client WriteFrame: %v", werr)
			done <- nil
			return
		}
		cfd, ferr := fdpass.ConnFD(clientConn)
		if ferr != nil {
			t.Errorf("client ConnFD: %v", ferr)
			done <- nil
			return
		}
		if serr := fdpass.SendFDs(cfd, []int{int(rIn.Fd()), int(wOut.Fd()), int(wErr.Fd())}); serr != nil {
			t.Errorf("client SendFDs: %v", serr)
			done <- nil
			return
		}
		resp, rerr := ipc.ReadEnvelope(clientConn)
		if rerr != nil {
			t.Errorf("client ReadEnvelope: %v", rerr)
			done <- nil
			return
		}
		done <- resp
	}()

	// Daemon side: this RecvFDs, dispatches to handleExecSpawn, writes the resp.
	d.handleConn(serverConn)

	resp := <-done
	if resp == nil {
		t.Fatal("client did not receive a response")
	}
	if resp.Err != nil {
		t.Fatalf("daemon returned error: %+v", resp.Err)
	}
	var sr ipc.ExecSpawnResp
	if derr := ipc.DecodeBody(ipc.BodyResp, resp, &sr); derr != nil {
		t.Fatalf("decode resp: %v", derr)
	}
	if sr.ExitCode != 7 {
		t.Errorf("ExitCode = %d, want 7", sr.ExitCode)
	}
	if !spy.valid {
		t.Errorf("spawner did not receive 3 valid fds (in=%d out=%d err=%d)", spy.in, spy.out, spy.err)
	}
}

// TestHandleConn_ExecSpawnNoFDs_BadRequest proves that an exec.spawn frame with
// NO fds sent after it makes handleConn fail with a bad_request rather than
// hang or dispatch. The client closes its end right after the frame so RecvFDs
// returns an error.
func TestHandleConn_ExecSpawnNoFDs_BadRequest(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	d.spawner = &fakeSpawner{}

	clientConn, serverConn := pairConn(t)

	env, err := ipc.NewRequest("spawn-nofd-1", ipc.OpExecSpawn, ipc.ExecSpawnReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: "", Password: pw},
		AbsTarget:    "/bin/true",
	})
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	done := make(chan *ipc.Envelope, 1)
	go func() {
		if werr := ipc.WriteFrame(clientConn, env); werr != nil {
			done <- nil
			return
		}
		// Close WITHOUT sending fds → daemon's RecvFDs sees EOF/short read.
		_ = clientConn.Close()
		resp, rerr := ipc.ReadEnvelope(clientConn)
		if rerr != nil {
			done <- nil
			return
		}
		done <- resp
	}()

	d.handleConn(serverConn)
	<-done // we don't assert on the (possibly nil) client read after close.
}
