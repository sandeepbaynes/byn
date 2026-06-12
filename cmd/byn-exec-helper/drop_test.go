package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// setUndumpable is the helper's memory-hardening step before execve
// (PR_SET_DUMPABLE=0 on Linux so a same-UID peer can't read the child's
// /proc/<pid>/environ; a no-op elsewhere). On every platform it must succeed
// and return nil — lowering one's own dumpable flag is unprivileged — so the
// drop sequence only hard-fails on a genuine error.
func TestSetUndumpableSucceeds(t *testing.T) {
	assert.NoError(t, setUndumpable())
}

func TestDropPlanOrder(t *testing.T) {
	plan := dropPlan(411, 411)
	assert.Equal(t, []string{
		"setgroups[]",
		"setresgid(411,411,411)",
		"setresuid(411,411,411)",
		"verify",
	}, plan)
}

func TestDropPlanRefusesRoot(t *testing.T) {
	assert.Panics(t, func() { dropPlan(0, 411) })
}

// TestExecTargetRejectsRelative confirms a non-absolute target is rejected
// BEFORE any exec. This is safely testable because execTarget returns the
// error before reaching unix.Exec (no PATH lookup, no process replacement).
func TestExecTargetRejectsRelative(t *testing.T) {
	err := execTarget([]string{"relativecmd"}, nil)
	assert.Error(t, err)
}
