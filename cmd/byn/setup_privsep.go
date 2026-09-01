package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/sandeepbaynes/byn/internal/config"
)

// privsepKeyPattern matches an existing `privsep = …` assignment, commented or
// not, so an explicit choice is recognised rather than duplicated.
var privsepKeyPattern = regexp.MustCompile(`(?m)^\s*privsep\s*=`)

// securitySectionPattern matches the [security] table header.
var securitySectionPattern = regexp.MustCompile(`(?m)^\s*\[security\]\s*$`)

// enablePrivsepInConfig turns privilege separation on as part of setup.
//
// Provisioning is necessary and not sufficient: `byn exec` asks the daemon
// whether privsep is on, and the daemon answers from `[security] privsep`. So a
// machine could be fully provisioned — service user, spawn helper, ACLs — and
// still run every exec child at the owner's UID because one key was never set.
// Setup is the moment byn has both root and the user's attention, and leaving
// the last step to a config edit meant the protection existed and was off.
//
// An explicit setting is never overwritten, including `privsep = false`: someone
// who turned it off did so on purpose, and setup is not the place to overrule
// them. Reports whether it changed anything, so the caller only restarts the
// daemon when there is something new to read.
func enablePrivsepInConfig(sysDir string, uid, gid int) (bool, error) {
	path := config.Path(sysDir)
	existing, err := os.ReadFile(path) //nolint:gosec // path is byn's own config, derived from the system data dir
	switch {
	case os.IsNotExist(err):
		existing = nil
	case err != nil:
		return false, fmt.Errorf("read config: %w", err)
	}

	body := string(existing)
	if privsepKeyPattern.MatchString(body) {
		return false, nil // already decided, either way
	}

	updated := insertPrivsep(body)
	tmp := path + ".tmp"
	if werr := os.WriteFile(tmp, []byte(updated), 0o600); werr != nil { //nolint:gosec // fixed path under the system data dir
		return false, fmt.Errorf("write config: %w", werr)
	}
	// The daemon runs as the service user and has to be able to read this.
	if uid > 0 && gid > 0 {
		if cerr := os.Chown(tmp, uid, gid); cerr != nil {
			_ = os.Remove(tmp)
			return false, fmt.Errorf("chown config: %w", cerr)
		}
	}
	if rerr := os.Rename(tmp, path); rerr != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("install config: %w", rerr)
	}
	return true, nil
}

// insertPrivsep adds `privsep = true` under [security], creating the table when
// the file does not have one.
//
// Text editing rather than parse-and-reserialise, because the config is
// hand-written and hand-read: round-tripping it through a struct would discard
// every comment in it, and the comments are how the file explains itself.
func insertPrivsep(body string) string {
	const line = "privsep = true  # exec children run as _byn-exec (added by byn setup)"

	if loc := securitySectionPattern.FindStringIndex(body); loc != nil {
		// Immediately after the header, so it reads as part of the table and
		// cannot land inside a later one.
		end := loc[1]
		if idx := strings.Index(body[end:], "\n"); idx >= 0 {
			end += idx + 1
		}
		return body[:end] + line + "\n" + body[end:]
	}

	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	if body != "" {
		body += "\n"
	}
	return body + "[security]\n" + line + "\n"
}
