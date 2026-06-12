package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
