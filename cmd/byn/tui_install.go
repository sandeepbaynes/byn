package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// errInstallDeclined means the person was asked and said no.
//
// A sentinel rather than a message the caller matches on: comparing errors by
// their text couples every caller to the wording, and the wording is the part
// most likely to be improved by somebody who does not know it is load-bearing.
var errInstallDeclined = errors.New("editor install declined")

// modulePath is byn's own module, used to fetch the editor from the same place
// byn itself came from.
const modulePath = "github.com/sandeepbaynes/byn"

// releaseVersion matches a version byn can ask the module proxy for. A build
// from a working tree reports something like "0.6.3-2-gabc1234-dirty", which
// names no published version.
var releaseVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)

// offerTUIInstall builds the editor with the Go toolchain when byn was installed
// with it and the editor was not.
//
// `go install` installs one main package per invocation, so a byn obtained that
// way arrives without its editor — the packaged installs all bundle it, and this
// is the one path that cannot. Rather than leave a documented second command
// nobody reads until `byn edit` fails, byn offers to run it.
//
// It ASKS first, every time, and never installs silently. Fetching and building
// code from the network is a supply-chain event, and a secrets manager doing
// that unannounced would be teaching exactly the reflex it exists to protect
// against. The prompt names the full command, so answering no leaves the user
// with something they can paste.
//
// Pinned to byn's own version, never @latest: an editor from a different release
// is a mismatch nobody asked for, and byn already reports version skew between
// its own parts as a fault.
func offerTUIInstall(dest string) (installed string, err error) {
	goBin, lookErr := exec.LookPath("go")
	if lookErr != nil {
		return "", fmt.Errorf("no Go toolchain to build it with")
	}
	ref := tuiModuleRef()
	fmt.Fprintf(os.Stderr, "%s %s\n", boldYellow("The editor is not installed."),
		dim("byn ships it, but `go install` takes one binary at a time."))
	fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Install it now?"), cyan("go install "+ref))
	fmt.Fprintf(os.Stderr, "%s ", dim("into "+dest+" [y/N]:"))

	if !confirmYes() {
		return "", errInstallDeclined
	}
	cmd := exec.Command(goBin, "install", ref) // #nosec G204 -- ref is byn's own module at byn's own version
	cmd.Env = append(os.Environ(), "GOBIN="+dest)
	cmd.Stdout = os.Stderr // build chatter is progress, not output
	cmd.Stderr = os.Stderr
	if runErr := cmd.Run(); runErr != nil {
		return "", fmt.Errorf("go install failed: %w", runErr)
	}
	return filepath.Join(dest, tuiBinary), nil
}

// tuiModuleRef is the module reference to install: byn's own version when it is
// a released one, and @latest otherwise.
//
// A development build reports a version no proxy knows, so pinning it would fail
// with a confusing error about an unknown revision. @latest is the honest
// fallback there, and a developer running a dev build is the one person equipped
// to notice a mismatch.
func tuiModuleRef() string {
	v := strings.TrimSpace(version)
	if !releaseVersion.MatchString(v) {
		return modulePath + "/cmd/" + tuiBinary + "@latest"
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return modulePath + "/cmd/" + tuiBinary + "@" + v
}

// confirmYes reads a single yes/no answer from the terminal.
//
// Defaults to no. This gate exists so that fetching and building code is a
// choice; a default of yes would make the prompt decoration.
func confirmYes() bool {
	var answer string
	if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}
