package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// warnIfProvisioningAnOlderByn says so when the byn running setup is not the
// only one on the machine and the others report different versions.
//
// This is the v0.5.4 lesson applied where it costs most. That release taught
// that an upgrade can install a byn nothing runs — `go install` puts one in a
// directory on no default PATH, an older byn elsewhere keeps answering, and
// `byn version` reports the old number right after a successful upgrade.
// `byn doctor` reports that disagreement now.
//
// setup is where the same confusion does damage rather than merely confusing.
// sudo resolves commands against secure_path and never the user's PATH, so
// `sudo byn setup` after installing to ~/.local/bin does not run the byn just
// installed: it runs whatever older copy sits in /usr/local/bin. That one
// provisions happily, installs ITS helper, reports success — and the person is
// told everything worked while the binary they upgraded to was never involved.
//
// A warning rather than a refusal. Provisioning an older byn on purpose is a
// legitimate thing to do — a downgrade, or a machine with two deliberate
// installs — and setup is not the place to overrule that. What it must not do
// is stay silent.
func warnIfProvisioningAnOlderByn(stderr io.Writer, installs []bynInstall) {
	if len(installs) < 2 {
		return
	}
	running := ""
	if exe, err := os.Executable(); err == nil {
		if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = resolved
		}
		running = exe
	}
	versions := map[string]bool{}
	for _, in := range installs {
		versions[in.Version] = true
	}
	if len(versions) < 2 {
		return // several copies, all the same build: nothing to confuse
	}

	_, _ = fmt.Fprintf(stderr, "\n%s %s\n", boldYellow("Warning:"),
		yellow("this machine has more than one byn, and they report different versions."))
	for _, in := range installs {
		mark := "  "
		if in.Path == running {
			mark = boldYellow("→ ")
		}
		_, _ = fmt.Fprintf(stderr, "%s%s = %s\n", mark, in.Path, in.Version)
	}
	_, _ = fmt.Fprintf(stderr, "%s\n",
		dim("The arrow marks the one provisioning now. sudo resolves commands against"))
	_, _ = fmt.Fprintf(stderr, "%s\n",
		dim("secure_path, never your own PATH, so this may not be the byn you just"))
	_, _ = fmt.Fprintf(stderr, "%s\n",
		dim(`installed. To provision a specific one: sudo "$(command -v byn)" setup`))
	_, _ = fmt.Fprintln(stderr)
}
