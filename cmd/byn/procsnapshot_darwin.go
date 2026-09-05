//go:build darwin

package main

import (
	"strconv"
	"strings"
)

// snapshotProcs returns the process table as the minimum a signal decision
// needs: who each process is, who its parent is, which account it runs as, and
// which process group it belongs to.
//
// macOS has no /proc, so this reads ps(1). It asks for its own fixed column set
// rather than reusing the `byn ps` one: that listing needs the command line and
// this needs the process group, and a shared format would make each carry a
// field the other has to skip.
func snapshotProcs() []procEntry {
	out := psOutput("-axo", "pid=,ppid=,uid=,pgid=")
	var procs []procEntry
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		nums := make([]int, 4)
		bad := false
		for i := 0; i < 4; i++ {
			n, err := strconv.Atoi(f[i])
			if err != nil {
				bad = true
				break
			}
			nums[i] = n
		}
		if bad {
			continue
		}
		procs = append(procs, procEntry{pid: nums[0], ppid: nums[1], uid: nums[2], pgid: nums[3]})
	}
	return procs
}
