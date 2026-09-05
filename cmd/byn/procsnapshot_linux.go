//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// snapshotProcs returns the process table by walking /proc — the Linux twin of
// the darwin ps(1) read. See the darwin file for why the shape is shared.
func snapshotProcs() []procEntry {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []procEntry
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, cerr := strconv.Atoi(e.Name())
		if cerr != nil {
			continue
		}
		dir := "/proc/" + e.Name()
		// The owning uid comes from the directory itself rather than from
		// status: procfs stamps /proc/<pid> with the process's uid, so one stat
		// answers it without parsing a text file that may be unreadable.
		fi, serr := os.Stat(dir)
		if serr != nil {
			continue
		}
		uid := -1
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid = int(st.Uid)
		}
		// #nosec G304 -- "/proc/<pid>/stat" built from a numeric procfs entry
		// we just enumerated; no caller-supplied path reaches this.
		b, rerr := os.ReadFile(dir + "/stat")
		if rerr != nil {
			continue
		}
		// The comm field is parenthesised and may itself contain spaces and
		// parens, so ppid is read from after the LAST ')' rather than by
		// splitting the whole line.
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 || i+1 >= len(s) {
			continue
		}
		fields := strings.Fields(s[i+1:])
		if len(fields) < 3 {
			continue
		}
		ppid, perr := strconv.Atoi(fields[1])
		if perr != nil {
			continue
		}
		// Field order after the comm is state, ppid, pgrp.
		pgid, gerr := strconv.Atoi(fields[2])
		if gerr != nil {
			continue
		}
		out = append(out, procEntry{pid: pid, ppid: ppid, uid: uid, pgid: pgid})
	}
	return out
}
