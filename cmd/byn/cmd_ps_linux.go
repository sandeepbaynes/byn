//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// findBynExecProcs returns all byn-managed exec processes by merging two scans:
//
//  1. Processes whose cmdline starts with "byn exec" — the privsep / spawn
//     path where the byn wrapper stays alive waiting for the child to exit.
//
//  2. Processes whose /proc/<pid>/environ contains BYN_EXEC_PID=<own-pid> —
//     the non-privsep path where syscall.Exec replaced the byn process with
//     the child.  The PID is unchanged after exec, so matching the env var
//     value against the process's own PID identifies it unambiguously.
//     Children inherit BYN_EXEC_PID but have different PIDs, so they are
//     excluded.
func findBynExecProcs() []bynExecProc {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	seen := make(map[int]struct{})
	var out []bynExecProc

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := "/proc/" + e.Name()

		// #nosec G304 -- dir is "/proc/<pid>" built from a numeric procfs entry
		// we just enumerated; no caller-supplied path reaches this.
		cb, err := os.ReadFile(dir + "/cmdline")
		if err != nil || len(cb) == 0 {
			continue
		}
		argv := strings.Split(strings.TrimRight(string(cb), "\x00"), "\x00")

		// Path 1: byn exec wrapper still alive.
		if len(argv) >= 2 && strings.HasSuffix(argv[0], "byn") && argv[1] == "exec" {
			seen[pid] = struct{}{}
			out = append(out, bynExecProc{
				pid:     pid,
				command: execCmdSummary(argv[2:]),
				project: projectOfPID(dir),
			})
			continue
		}

		// Path 2: process replaced via syscall.Exec — look for BYN_EXEC_PID=<pid>.
		// #nosec G304 -- same fixed procfs path as above.
		eb, err := os.ReadFile(dir + "/environ")
		if err != nil || len(eb) == 0 {
			continue
		}
		if _, already := seen[pid]; already {
			continue
		}
		marker := "BYN_EXEC_PID=" + strconv.Itoa(pid)
		for _, kv := range strings.Split(string(eb), "\x00") {
			if kv == marker {
				seen[pid] = struct{}{}
				out = append(out, bynExecProc{
					pid:     pid,
					command: strings.Join(argv, " "),
					project: projectOfPID(dir),
				})
				break
			}
		}
	}
	return out
}

// findChildren returns the direct child PIDs of parentPID by scanning /proc.
func findChildren(parentPID int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 || i+1 >= len(s) {
			continue
		}
		fields := strings.Fields(s[i+1:])
		if len(fields) < 2 {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1])
		if ppid == parentPID {
			out = append(out, pid)
		}
	}
	return out
}

// execCmdSummary extracts the human-readable command from the args that
// follow "exec". It strips byn-level flags and the "--" separator so
// only the child command and its arguments are shown.
//
//	byn exec -- pnpm start       → "pnpm start"
//	byn exec --vault w -- npm i  → "npm i"
//	byn exec myalias             → "myalias"
func execCmdSummary(rest []string) string {
	for i, a := range rest {
		if a == "--" {
			return strings.Join(rest[i+1:], " ")
		}
		// First non-flag token is either an alias name or the command.
		if !strings.HasPrefix(a, "-") {
			return strings.Join(rest[i:], " ")
		}
	}
	return strings.Join(rest, " ")
}

// projectOfPID returns the directory of the .byn governing a running child, by
// reading its working directory and walking up — the same discovery byn does
// when it resolves scope, so the answer matches the file that actually applies.
//
// Best-effort: an unreadable cwd (the child belongs to the exec service user
// under privilege separation, and /proc/<pid>/cwd is owner-only) yields "", and
// the column reads "-" rather than a guess.
func projectOfPID(procDir string) string {
	cwd, err := os.Readlink(procDir + "/cwd")
	if err != nil || cwd == "" {
		return ""
	}
	for dir := cwd; ; {
		if _, statErr := os.Stat(filepath.Join(dir, ".byn")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir { // reached the root without finding one
			return ""
		}
		dir = parent
	}
}
