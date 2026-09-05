package main

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// The bug this pins: repair.go shelled out to setfacl unconditionally, with no
// build tag, so on macOS — which has no setfacl — `byn repair` walked the tree,
// failed on every file, and reported "nothing to repair".
func TestACLOwnerCmd_UsesThePlatformTool(t *testing.T) {
	cmd := aclOwnerCmd("/tmp/x", "someone", false)
	want := "setfacl"
	if runtime.GOOS == "darwin" {
		want = "chmod"
	}
	if !strings.HasSuffix(cmd.Path, want) && cmd.Args[0] != want {
		t.Fatalf("uses %q, want %q on %s", cmd.Args[0], want, runtime.GOOS)
	}
	// The path must reach the command, or the repair silently touches nothing.
	if cmd.Args[len(cmd.Args)-1] != "/tmp/x" {
		t.Errorf("path not passed: %v", cmd.Args)
	}
}

func TestACLOwnerCmd_DistinguishesFilesFromDirs(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("only darwin varies the permission set by file type")
	}
	// macOS rejects nothing here but the vocabularies differ: add_file and
	// add_subdirectory are meaningless on a regular file, and a directory that
	// only got read,write cannot have entries created in it.
	dir := strings.Join(aclOwnerCmd("/tmp/d", "someone", true).Args, " ")
	file := strings.Join(aclOwnerCmd("/tmp/f", "someone", false).Args, " ")
	if !strings.Contains(dir, "add_subdirectory") {
		t.Errorf("directory grant lacks add_subdirectory: %s", dir)
	}
	if strings.Contains(file, "add_subdirectory") {
		t.Errorf("file grant should not carry directory rights: %s", file)
	}
}

func TestACLPrincipal_ResolvesTheCaller(t *testing.T) {
	got, err := aclPrincipal(os.Getuid())
	if err != nil {
		t.Fatalf("aclPrincipal(%d): %v", os.Getuid(), err)
	}
	if got == "" {
		t.Fatal("empty principal")
	}
	// macOS chmod cannot translate a numeric id ("Unable to translate '501' to
	// a UUID"), so darwin must hand back a name, not the digits.
	if runtime.GOOS == "darwin" && strings.Trim(got, "0123456789") == "" {
		t.Fatalf("darwin needs a username, got the numeric uid %q", got)
	}
}

func TestACLToolAvailable(t *testing.T) {
	// chmod is in every PATH; setfacl is not on every Linux box, so this only
	// asserts the check answers rather than what it answers.
	if err := aclToolAvailable(); err != nil && runtime.GOOS == "darwin" {
		t.Fatalf("chmod should be present on darwin: %v", err)
	}
}
