package main

import (
	"fmt"
	"os"
	"text/tabwriter"
)

// bynExecProc describes a running "byn exec" wrapper process and the
// command it launched.
type bynExecProc struct {
	pid     int
	command string // everything after the "--" or alias boundary in argv
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
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "PID\tCOMMAND")
	for _, j := range jobs {
		_, _ = fmt.Fprintf(w, "%d\t%s\n", j.pid, j.command)
	}
	_ = w.Flush()
	return 0
}
