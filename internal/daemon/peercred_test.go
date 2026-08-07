package daemon

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPeerCred_UnixSocketReportsSelf is a DIRECT test of the peer-credential
// path — the authorization trust anchor that every access decision rests on.
// It was previously exercised only transitively; a direct test pins the
// contract: a Unix-socket peer's UID is read back correctly as our own.
func TestPeerCred_UnixSocketReportsSelf(t *testing.T) {
	dir := shortTempDir(t) // macOS caps unix socket paths at ~104 chars
	sockPath := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := l.Accept()
		if aerr != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	client, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var srv net.Conn
	select {
	case srv = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("accept timed out")
	}
	if srv == nil {
		t.Fatal("accept failed")
	}
	defer srv.Close()

	uid, _, err := peerCred(srv)
	if err != nil {
		t.Fatalf("peerCred: %v", err)
	}
	if want := uint32(os.Getuid()); uid != want {
		t.Fatalf("peerCred uid = %d, want %d", uid, want)
	}
}

// TestPeerCred_NonUnixReturnsErrNotUnix confirms a non-Unix-socket connection
// is reported as ErrNotUnix (the in-proc/test bypass class) rather than a
// spurious UID — handleConn relies on this to distinguish the two.
func TestPeerCred_NonUnixReturnsErrNotUnix(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, _, err := peerCred(a); !errors.Is(err, ErrNotUnix) {
		t.Fatalf("peerCred on net.Pipe = %v, want ErrNotUnix", err)
	}
}
