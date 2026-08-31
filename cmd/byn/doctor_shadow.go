package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// bynInstallDirs are the places a byn realistically ends up. GOBIN and GOPATH
// are read from the environment because that is where `go install` puts things
// and the default is not the only answer.
func bynInstallDirs() []string {
	dirs := []string{"/usr/local/bin", "/usr/bin", "/opt/homebrew/bin"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".local", "bin"), filepath.Join(home, "go", "bin"))
	}
	if gobin := os.Getenv("GOBIN"); gobin != "" {
		dirs = append(dirs, gobin)
	}
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		dirs = append(dirs, filepath.Join(gopath, "bin"))
	}
	return dirs
}

// bynInstall is one byn found on disk and what it says its version is.
type bynInstall struct {
	Path    string
	Version string
	OnPath  bool
}

// findBynInstalls locates every byn on this machine and asks each its version.
//
// This exists because of a failure with no symptom. `go install …@latest`
// succeeded, put a new byn in ~/go/bin, and ~/go/bin was not on PATH — so the
// byn that ran was an older one in ~/.local/bin, and `byn version` reported the
// old number immediately after a successful upgrade. Nothing was broken and
// nothing said anything: the install worked, the wrong binary answered.
func findBynInstalls(runVersion func(string) string) []bynInstall {
	pathDirs := map[string]bool{}
	for _, p := range strings.Split(os.Getenv("PATH"), string(os.PathListSeparator)) {
		if p != "" {
			pathDirs[filepath.Clean(p)] = true
		}
	}
	seen := map[string]bool{}
	var out []bynInstall
	for _, dir := range bynInstallDirs() {
		p := filepath.Join(dir, "byn")
		if seen[p] {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() || fi.Mode().Perm()&0o111 == 0 {
			continue
		}
		seen[p] = true
		out = append(out, bynInstall{Path: p, Version: runVersion(p), OnPath: pathDirs[filepath.Clean(dir)]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// bynVersionOf asks a byn binary what it is. Best-effort: a binary that will not
// run is reported as unknown rather than omitted, since its presence is the
// interesting part.
func bynVersionOf(path string) string {
	cmd := exec.Command(path, "version") // #nosec G204 -- path comes from a fixed list of install dirs
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(strings.TrimPrefix(first, "byn "))
}

// diagnoseShadowedInstalls reports byn binaries that disagree about the version.
//
// One byn, or several agreeing, is fine and says so quietly. Several that
// disagree is worth a failed check: whichever one PATH finds first is the one
// that answers, and after an upgrade that is not necessarily the newest.
func diagnoseShadowedInstalls(installs []bynInstall) []healCheck {
	if len(installs) < 2 {
		return nil
	}
	versions := map[string]bool{}
	for _, in := range installs {
		versions[in.Version] = true
	}
	lines := make([]string, 0, len(installs))
	for _, in := range installs {
		mark := ""
		if !in.OnPath {
			mark = " (not on your PATH)"
		}
		lines = append(lines, fmt.Sprintf("%s = %s%s", in.Path, in.Version, mark))
	}
	detail := strings.Join(lines, "; ")
	if len(versions) == 1 {
		return []healCheck{{Name: "one byn on this machine", OK: true, Detail: detail}}
	}
	return []healCheck{{
		Name:   "one byn on this machine",
		OK:     false,
		Detail: detail,
		Fix: "several byn binaries disagree — the first on your PATH is the one that runs, " +
			"which after an upgrade may not be the newest. Remove the stale ones, or install " +
			"with GOBIN pointing at a directory already on your PATH.",
	}}
}
