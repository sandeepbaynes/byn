package privsep

import (
	"errors"
	"regexp"
)

// programArgumentsFirst finds the first <string> inside the ProgramArguments
// array of a launchd plist — the binary launchd execs.
var programArgumentsFirst = regexp.MustCompile(
	`(?s)<key>ProgramArguments</key>\s*<array>\s*<string>([^<]+)</string>`)

// ErrNoServiceExecPath is returned when a plist names no program.
var ErrNoServiceExecPath = errors.New("launchd plist has no ProgramArguments")

// ServiceExecPathFromPlist returns the binary a byn LaunchDaemon plist runs.
//
// It exists so the CLI can tell the owner WHICH file to grant Full Disk Access
// to. The CLI's own path is the wrong answer often enough to matter: a machine
// with a `go install` copy on PATH and the provisioned copy in /usr/local/bin
// would name the one launchd does not run, and a grant to the wrong binary is
// indistinguishable from no grant at all — the same "operation not permitted",
// after the owner did exactly what was asked.
//
// This reads the plist byn writes (launchDaemonPlist), not arbitrary plists;
// the first ProgramArguments entry is the program by launchd's contract.
func ServiceExecPathFromPlist(plist []byte) (string, error) {
	m := programArgumentsFirst.FindSubmatch(plist)
	if m == nil {
		return "", ErrNoServiceExecPath
	}
	return string(m[1]), nil
}
