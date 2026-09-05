//go:build darwin

package main

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

// macOS has no /proc, so the process table is read through ps(1) rather than by
// walking a filesystem. That is the whole reason this file exists separately
// from the Linux one: the identifying facts are the same, the way to obtain
// them is not.
//
// ps is called with explicit "=" empty headers so there is no header line to
// skip, and with a fixed column order, so the output shape is ours rather than
// whatever the user's PS_FORMAT or locale would produce.
const (
	psListArgs = "-axo"
	psListFmt  = "pid=,ppid=,uid=,command="
	// psTimeout bounds the ps and lsof calls. `byn ps` is a diagnostic run when
	// something is already wrong; hanging on a wedged filesystem would be worse
	// than an incomplete answer.
	psTimeout = 3 * time.Second
)

// psRow is one line of the process table.
type psRow struct {
	pid     int
	ppid    int
	uid     int
	command string
}

// parsePSRows turns ps output into rows.
//
// It is separated from the call that produces it so the parsing can be tested
// against known bytes. A platform file that compiles proves nothing about what
// it does — which is exactly how the writable-path reconcile shipped as a no-op
// here — so the shape of the output is asserted rather than assumed.
//
// The first three fields are numeric and fixed-width-ish; everything after them
// is the command, which may itself contain spaces. Splitting on the first three
// boundaries only is what keeps "bash /path/with a space/x.sh" intact.
func parsePSRows(out string) []psRow {
	var rows []psRow
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		// Rejoin the command from the original line rather than from Fields, so
		// runs of spaces inside it survive.
		idx := indexAfterNFields(line, 3)
		if idx < 0 {
			continue
		}
		rows = append(rows, psRow{
			pid:     pid,
			ppid:    ppid,
			uid:     uid,
			command: strings.TrimSpace(line[idx:]),
		})
	}
	return rows
}

// indexAfterNFields returns the byte offset just past the nth whitespace-
// separated field, or -1 if the line has fewer.
func indexAfterNFields(line string, n int) int {
	i, seen := 0, 0
	for seen < n {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			return -1
		}
		for i < len(line) && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		seen++
	}
	return i
}

// isBynExecWrapper reports whether a command line is a live `byn exec` wrapper,
// and returns the command it was asked to run.
//
// argv[0] is matched on its base name so that ./bin/byn, /usr/local/bin/byn and
// a bare byn are all recognised — during development the binary is routinely run
// from the build directory, and a ps that only sees the installed path would
// quietly list nothing.
func isBynExecWrapper(command string) (string, bool) {
	tokens := strings.Fields(command)
	if len(tokens) < 2 || tokens[1] != "exec" {
		return "", false
	}
	base := tokens[0]
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if base != "byn" {
		return "", false
	}
	return summarizeExecCommand(tokens[2:]), true
}

// summarizeExecCommand reduces `byn exec` arguments to the command a person
// would recognise: everything after "--", or the first non-flag token onward,
// which is either an alias or the command itself.
//
// It works on whitespace-split tokens because that is all ps gives — the kernel
// stores argv, but ps hands back one string, so an argument that contained a
// space is indistinguishable from two arguments. The rendering is for a human
// picking a PID out of a list, and it is honest about being a summary.
func summarizeExecCommand(rest []string) string {
	// The "--" boundary is looked for across the WHOLE argument list before
	// falling back, and that ordering is the point. Scanning left to right and
	// stopping at the first non-flag token treats the VALUE of a preceding flag
	// as the command: `--vault w -- npm i` yields "w -- npm i", naming a vault
	// where a command should be. Where an explicit boundary exists it is the
	// only unambiguous answer, so it wins.
	for i, a := range rest {
		if a == "--" {
			return strings.Join(rest[i+1:], " ")
		}
	}
	// No boundary: the first non-flag token is an alias, and everything from
	// there is the command. A flag's value cannot be mistaken for it here,
	// because a form that takes one would have needed the boundary.
	for i, a := range rest {
		if !strings.HasPrefix(a, "-") {
			return strings.Join(rest[i:], " ")
		}
	}
	return strings.Join(rest, " ")
}

// classifyExecProcs picks the byn-managed processes out of a process table.
//
// Three shapes count, and they are deliberately different questions:
//
//  1. The `byn exec` wrapper. Under privilege separation it stays alive waiting
//     for the child, so it is the thing you actually want to signal — killing it
//     takes the process group with it.
//
//  2. A process running as the exec service user that is NOT already under a
//     listed wrapper. That account exists for nothing else, so its uid is proof
//     on its own — which matters because a privsep child's environment is
//     unreadable by the owner, so the marker in rule 3 cannot be seen.
//     Descendants of a listed wrapper are deliberately excluded: the wrapper is
//     the job, and a shell script looping over `sleep` would otherwise put a row
//     per iteration in the list. What survives this filter is the case worth
//     seeing — an orphan whose wrapper is gone, which is exactly what you would
//     want to kill.
//
//  3. A process carrying BYN_EXEC_PID equal to its own pid. This is the
//     unprovisioned path, where syscall.Exec replaced byn with the child, so the
//     pid never changed. Children inherit the variable but have different pids,
//     which is what keeps them out.
//
// execUID is -1 when the service account does not exist (an unprovisioned
// machine), which disables rule 2 rather than matching uid -1 against anything.
func classifyExecProcs(rows []psRow, execUID int, markers map[int]bool) []bynExecProc {
	var out []bynExecProc
	seen := make(map[int]bool, len(rows))

	// Wrappers first, so rule 2 can tell an orphan from a process that already
	// has a row.
	wrappers := map[int]bool{}
	uidOf := make(map[int]int, len(rows))
	for _, r := range rows {
		uidOf[r.pid] = r.uid
	}
	for _, r := range rows {
		if cmd, ok := isBynExecWrapper(r.command); ok {
			wrappers[r.pid] = true
			seen[r.pid] = true
			out = append(out, bynExecProc{pid: r.pid, command: cmd})
		}
	}

	for _, r := range rows {
		if seen[r.pid] {
			continue
		}
		if execUID >= 0 && r.uid == execUID && !systemDaemonCommand(r.command) &&
			topmostExecProc(r, wrappers, uidOf, execUID) {
			seen[r.pid] = true
			out = append(out, bynExecProc{pid: r.pid, command: r.command})
			continue
		}
		if markers[r.pid] {
			seen[r.pid] = true
			out = append(out, bynExecProc{pid: r.pid, command: r.command})
		}
	}
	return out
}

// systemDaemonCommand reports whether a command line is one of the per-user
// daemons launchd starts for ANY account, rather than something byn ran.
//
// Rule 2 identifies a job by its uid alone, and macOS gives the exec service
// account the same treatment it gives a person: distnoted and lsd get spawned
// for it whether or not byn is doing anything. They then appear in the one
// listing someone consults to find a stuck dev server, and `byn kill --all`
// would signal them — so they are excluded where the uid is the only evidence.
// Rules 1 and 3 are unaffected: those identify a process by what it IS.
func systemDaemonCommand(command string) bool {
	for _, prefix := range []string{"/usr/sbin/", "/usr/libexec/", "/System/"} {
		if strings.HasPrefix(command, prefix) {
			return true
		}
	}
	return false
}

// topmostExecProc reports whether an exec-user process is the head of its job
// rather than something deeper inside one.
//
// The test is its parent: a process whose parent is a listed wrapper is that
// wrapper's job, and one whose parent is itself the exec user is deeper still.
// Only a process hanging off something else — launchd, after its wrapper died —
// is a row worth printing.
//
// This is a parent test rather than a walk of the whole subtree because a
// process table is a snapshot: pids get reused, so the parent chain it describes
// is not guaranteed acyclic, and one hop cannot loop.
func topmostExecProc(r psRow, wrappers map[int]bool, uidOf map[int]int, execUID int) bool {
	if wrappers[r.ppid] {
		return false
	}
	if pu, known := uidOf[r.ppid]; known && pu == execUID {
		return false
	}
	return true
}

// psOutput runs ps and returns its stdout, or "" if it could not be read.
func psOutput(args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), psTimeout)
	defer cancel()
	b, err := exec.CommandContext(ctx, "ps", args...).Output() // #nosec G204 -- fixed argv
	if err != nil {
		return ""
	}
	return string(b)
}

// execServiceUID resolves the exec service account, or -1 when it does not
// exist — which is the normal state on a machine where setup has not run.
func execServiceUID() int {
	u, err := user.Lookup(privsep.ExecUser)
	if err != nil {
		return -1
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1
	}
	return uid
}

// markerPIDs returns the pids whose own environment carries BYN_EXEC_PID set to
// that pid — rule 3 above.
//
// `ps -E` only reveals the environment of processes the caller owns, which is
// precisely the case this rule is for: without privilege separation the exec
// child runs as you. Where privsep IS engaged the environment is unreadable by
// design, and rule 2 covers it instead.
func markerPIDs() map[int]bool {
	out := psOutput("-axEo", "pid=,command=")
	if out == "" {
		return nil
	}
	found := map[int]bool{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		if strings.Contains(line, "BYN_EXEC_PID="+strconv.Itoa(pid)) {
			found[pid] = true
		}
	}
	return found
}

// findBynExecProcs returns the byn-managed exec processes running now.
func findBynExecProcs() []bynExecProc {
	rows := parsePSRows(psOutput(psListArgs, psListFmt))
	if len(rows) == 0 {
		return nil
	}
	procs := classifyExecProcs(rows, execServiceUID(), markerPIDs())
	for i := range procs {
		procs[i].project = projectOfPID(procs[i].pid)
	}
	return procs
}

// projectOfPID returns the directory of the .byn governing a running child.
//
// macOS keeps no readable link to another process's cwd, so this asks lsof.
// Best-effort by design: lsof answers for processes the caller owns, so the
// `byn exec` wrapper (yours) resolves and a privsep child (the service user's)
// does not. That is the same outcome Linux reaches by a different route, where
// /proc/<pid>/cwd is owner-only — and the wrapper is the row that matters, since
// it is the one holding the project's cwd.
func projectOfPID(pid int) string {
	ctx, cancel := context.WithTimeout(context.Background(), psTimeout)
	defer cancel()
	// -Fn prints one field per line, "n"-prefixed: machine-readable, unlike the
	// column layout, which is aligned for people and shifts with path length.
	b, err := exec.CommandContext(ctx, "lsof", //nolint:gosec // fixed argv
		"-a", "-p", strconv.Itoa(pid), "-d", "cwd", "-Fn").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "n") {
			continue
		}
		return bynDirAbove(strings.TrimPrefix(line, "n"))
	}
	return ""
}

// bynDirAbove walks up from dir to the first directory holding a .byn — the
// same discovery byn does when it resolves scope, so the answer names the file
// that actually applies rather than the nearest one.
func bynDirAbove(dir string) string {
	if dir == "" {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".byn")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir { // reached the root without finding one
			return ""
		}
		dir = parent
	}
}
