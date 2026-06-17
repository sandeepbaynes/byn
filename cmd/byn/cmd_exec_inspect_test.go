package main

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestStripInspect(t *testing.T) {
	cases := []struct {
		name      string
		in        []string
		wantOut   []string
		wantBrk   bool
		wantValue string
		wantFound bool
	}{
		{"absent", []string{"--", "node", "x"}, []string{"--", "node", "x"}, false, "", false},
		{"bare inspect", []string{"--inspect", "--", "node"}, []string{"--", "node"}, false, "", true},
		{"attached port", []string{"--inspect=9230", "--", "node"}, []string{"--", "node"}, false, "9230", true},
		{"space port", []string{"--inspect", "9230", "--", "node"}, []string{"--", "node"}, false, "9230", true},
		{"space zero", []string{"--inspect", "0", "--", "node"}, []string{"--", "node"}, false, "0", true},
		{"space host:port", []string{"--inspect", "127.0.0.1:9230", "--", "node"}, []string{"--", "node"}, false, "127.0.0.1:9230", true},
		{"brk attached", []string{"--inspect-brk=9231", "--", "node"}, []string{"--", "node"}, true, "9231", true},
		{"brk space", []string{"--inspect-brk", "9231", "--", "node"}, []string{"--", "node"}, true, "9231", true},
		{"bare then alias (not a port)", []string{"--inspect", "deploy"}, []string{"deploy"}, false, "", true},
		{"bare then sep", []string{"--inspect", "--", "node"}, []string{"--", "node"}, false, "", true},
		{"after sep is child argv", []string{"--", "node", "--inspect"}, []string{"--", "node", "--inspect"}, false, "", false},
		{"with other byn flag", []string{"--inspect", "--no-privsep", "--", "node"}, []string{"--no-privsep", "--", "node"}, false, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, brk, value, found := stripInspect(tc.in)
			if found != tc.wantFound || brk != tc.wantBrk || value != tc.wantValue {
				t.Errorf("got found=%v brk=%v value=%q; want found=%v brk=%v value=%q",
					found, brk, value, tc.wantFound, tc.wantBrk, tc.wantValue)
			}
			if strings.Join(out, "\x00") != strings.Join(tc.wantOut, "\x00") {
				t.Errorf("out = %v, want %v", out, tc.wantOut)
			}
		})
	}
}

func TestLooksLikePort(t *testing.T) {
	yes := []string{"9230", "0", "127.0.0.1:9230", "65535"}
	no := []string{"deploy", "", "--flag", "node", "abc:def", "9230x"}
	for _, s := range yes {
		if !looksLikePort(s) {
			t.Errorf("looksLikePort(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if looksLikePort(s) {
			t.Errorf("looksLikePort(%q) = true, want false", s)
		}
	}
}

func TestResolveInspect_NoTarget_AllocatesFreePort(t *testing.T) {
	flag, hint, err := resolveInspect(false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(flag, "--inspect=127.0.0.1:") {
		t.Fatalf("flag = %q, want a 127.0.0.1:<port> target", flag)
	}
	port := strings.TrimPrefix(flag, "--inspect=127.0.0.1:")
	if p, perr := strconv.Atoi(port); perr != nil || p <= 0 {
		t.Errorf("allocated port %q is not a positive integer", port)
	}
	if !strings.Contains(hint, "attach") {
		t.Errorf("hint should tell the user to attach: %q", hint)
	}

	// --inspect-brk → break-on-start flag.
	if flag, _, _ := resolveInspect(true, ""); !strings.HasPrefix(flag, "--inspect-brk=127.0.0.1:") {
		t.Errorf("brk flag = %q, want --inspect-brk=127.0.0.1:<port>", flag)
	}
}

func TestResolveInspect_Zero_PassesThrough(t *testing.T) {
	flag, _, err := resolveInspect(false, "0")
	if err != nil || flag != "--inspect=0" {
		t.Errorf("resolveInspect(0) = (%q, %v), want (--inspect=0, nil)", flag, err)
	}
}

func TestResolveInspect_ExplicitFreePort_Used(t *testing.T) {
	// Grab a free port, release it, then ask byn to use it — it should be free.
	port, err := freeTCPPort()
	if err != nil {
		t.Skipf("could not allocate a port: %v", err)
	}
	flag, _, rerr := resolveInspect(false, strconv.Itoa(port))
	if rerr != nil {
		t.Fatalf("explicit free port rejected: %v", rerr)
	}
	want := "--inspect=127.0.0.1:" + strconv.Itoa(port)
	if flag != want {
		t.Errorf("flag = %q, want %q", flag, want)
	}
}

func TestResolveInspect_PortInUse_Errors(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	port := l.Addr().(*net.TCPAddr).Port

	_, _, rerr := resolveInspect(false, strconv.Itoa(port))
	if rerr == nil {
		t.Fatalf("resolveInspect on an in-use port must error")
	}
	if !strings.Contains(rerr.Error(), "already in use") {
		t.Errorf("error = %q, want it to mention 'already in use'", rerr)
	}
}

func TestResolveInspect_InvalidPort_Errors(t *testing.T) {
	for _, bad := range []string{"98769", "notaport", "-1"} {
		if _, _, err := resolveInspect(false, bad); err == nil {
			t.Errorf("resolveInspect(%q) should error", bad)
		}
	}
}

func TestApplyInspect_MergesNodeOptions(t *testing.T) {
	t.Setenv("NODE_OPTIONS", "--max-old-space-size=4096")
	if err := applyInspect(false, "0"); err != nil {
		t.Fatalf("applyInspect: %v", err)
	}
	s := os.Getenv("NODE_OPTIONS")
	if !strings.Contains(s, "--max-old-space-size=4096") {
		t.Errorf("NODE_OPTIONS dropped the existing value: %q", s)
	}
	if !strings.Contains(s, "--inspect=0") {
		t.Errorf("NODE_OPTIONS missing the inspector flag: %q", s)
	}
}

func TestApplyInspect_BadPort_ReturnsError(t *testing.T) {
	if err := applyInspect(false, "98769"); err == nil {
		t.Error("applyInspect with an out-of-range port must return an error")
	}
}
