package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaunchdPlist(t *testing.T) {
	p := launchdPlist("/usr/local/bin/byn")
	for _, want := range []string{
		"<string>" + launchdLabel + "</string>",
		"<string>/usr/local/bin/byn</string>",
		"<string>start</string>",
		"<string>--foreground</string>",
		"<key>RunAtLoad</key>",
		"<key>KeepAlive</key>",
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("plist missing %q:\n%s", want, p)
		}
	}
	// The data root is the fixed system path — the plist must not inject any
	// EnvironmentVariables data-dir override.
	if strings.Contains(p, "EnvironmentVariables") {
		t.Fatalf("plist must not carry a data-dir env override:\n%s", p)
	}
}

func TestSystemdUnit(t *testing.T) {
	u := systemdUnit("/usr/local/bin/byn")
	for _, want := range []string{
		"ExecStart=/usr/local/bin/byn start --foreground",
		"Restart=on-failure",
		"WantedBy=default.target",
	} {
		if !strings.Contains(u, want) {
			t.Fatalf("unit missing %q:\n%s", want, u)
		}
	}
	// The data root is the fixed system path — the unit must not inject any
	// Environment= data-dir override.
	if strings.Contains(u, "Environment=") {
		t.Fatalf("unit must not carry a data-dir env override:\n%s", u)
	}
}

// The generated plist must be a well-formed property list (B1 exit criterion).
func TestLaunchdPlist_PlutilLint(t *testing.T) {
	if _, err := exec.LookPath("plutil"); err != nil {
		t.Skip("plutil unavailable (non-macOS)")
	}
	f := filepath.Join(t.TempDir(), "byn.plist")
	if err := os.WriteFile(f, []byte(launchdPlist("/usr/local/bin/byn")), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("plutil", "-lint", f).CombinedOutput(); err != nil { // #nosec G204 -- fixed argv + temp path
		t.Fatalf("plutil -lint rejected the plist: %v\n%s", err, out)
	}
}

func TestDaemonServiceSpec(t *testing.T) {
	spec, err := daemonServiceSpec()
	if err != nil {
		t.Skipf("unsupported platform: %v", err)
	}
	if spec.path == "" || spec.content == "" || len(spec.load) == 0 || len(spec.unload) == 0 {
		t.Fatalf("incomplete spec: %+v", spec)
	}
	if !strings.HasSuffix(spec.path, ".plist") && !strings.HasSuffix(spec.path, ".service") {
		t.Fatalf("unexpected service path: %s", spec.path)
	}
}
