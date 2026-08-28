package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// bynExecProc describes a running "byn exec" wrapper process and the
// command it launched.
type bynExecProc struct {
	pid     int
	command string // everything after the "--" or alias boundary in argv
	// project is the directory holding the .byn that governs this child, or ""
	// when none was found. With eight children listed, the command alone leaves
	// you guessing which one is "the api"; the project is what tells them apart.
	project string
}

// runPS lists byn-managed exec processes. It scans the OS process table
// for live "byn exec" wrapper processes and prints each one's PID and
// the command it is running. No daemon IPC needed — all data comes from
// the kernel's process table.
func runPS(_ []string) int {
	jobs := findBynExecProcs()
	if len(jobs) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "no byn exec processes found")
		return 0
	}
	// The project column appears only when byn could work one out, so a
	// single-project machine keeps the output it had.
	anyProject := false
	for _, j := range jobs {
		if j.project != "" {
			anyProject = true
		}
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if anyProject {
		_, _ = fmt.Fprintln(w, "PID\tPROJECT\tCOMMAND")
	} else {
		_, _ = fmt.Fprintln(w, "PID\tCOMMAND")
	}
	for _, j := range jobs {
		if anyProject {
			_, _ = fmt.Fprintf(w, "%d\t%s\t%s\n", j.pid, dashIfEmpty(tildeHome(j.project)), j.command)
			continue
		}
		_, _ = fmt.Fprintf(w, "%d\t%s\n", j.pid, j.command)
	}
	_ = w.Flush()
	return 0
}

// tildeHome abbreviates a path under the caller's home as "~/…". Eight rows of
// absolute paths pushed the command column off the screen, which defeats the
// point of showing both.
func tildeHome(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || p == home {
		return p
	}
	if rest, ok := strings.CutPrefix(p, home+string(os.PathSeparator)); ok {
		return "~" + string(os.PathSeparator) + rest
	}
	return p
}

// dashIfEmpty renders a missing value as "-" rather than a blank column.
func dashIfEmpty(v string) string {
	if v == "" {
		return "-"
	}
	return v
}
