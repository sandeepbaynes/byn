package main

// doctor_skill.go reports an installed Agent Skill that no longer matches the
// installed byn.
//
// A skill describes a CLI's behaviour, so a stale one is not merely unhelpful —
// it actively instructs an agent to use a version it is not running, and the
// agent has no way to notice. `byn skill install` rewrites it from the binary,
// which is why the fix is one command and why this only has to point at it.

import "fmt"

// checkSkillFresh reports on the Agent Skill, or says nothing when none is
// installed.
//
// Absence is deliberately NOT a finding. byn is used plenty without an AI agent,
// and a permanent line telling those people to install something they do not
// want is exactly the noise that teaches people to skip doctor's output — the
// same reasoning that keeps a needless Full Disk Access grant from reporting as
// a failure.
func checkSkillFresh() (healCheck, bool) {
	installed, path := installedSkillVersion()
	if path == "" {
		return healCheck{}, false
	}
	if installed == "" {
		return healCheck{
			Name: "agent skill up to date", OK: false, Warn: true,
			Detail: path + " declares no version",
			Fix:    "run: byn skill install",
		}, true
	}
	if installed == version {
		return healCheck{Name: "agent skill up to date", OK: true, Detail: installed}, true
	}
	return healCheck{
		Name: "agent skill up to date", OK: false, Warn: true,
		Detail: fmt.Sprintf("%s documents %s, this byn is %s — an agent is following instructions for a version you are not running",
			path, installed, version),
		Fix: "run: byn skill install",
	}, true
}
