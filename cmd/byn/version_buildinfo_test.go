package main

import (
	"runtime/debug"
	"testing"
)

func bi(mainVersion string, settings ...debug.BuildSetting) *debug.BuildInfo {
	return &debug.BuildInfo{
		Main:     debug.Module{Version: mainVersion},
		Settings: settings,
	}
}

// `go install github.com/sandeepbaynes/byn/cmd/byn@latest` applies none of the
// release ldflags, so byn reported "0.0.1" — the placeholder — while being a
// perfectly good v0.5.0. Go embeds the module version in the binary; when
// nothing was stamped, that is the answer.
func TestFromBuildInfo_GoInstallReportsTheModuleVersion(t *testing.T) {
	ver, sha, date := fromBuildInfo(bi("v0.5.0"), defaultVersion, "", "")
	if ver != "0.5.0" {
		t.Errorf("version = %q, want 0.5.0", ver)
	}
	if sha != "" || date != "" {
		t.Errorf("invented commit/date from nothing: %q %q", sha, date)
	}
}

// A stamped build knows more than the module version does — `git describe`
// carries the commits since the tag — so it must never be overwritten.
func TestFromBuildInfo_StampedWins(t *testing.T) {
	ver, sha, date := fromBuildInfo(
		bi("v0.5.0", debug.BuildSetting{Key: "vcs.revision", Value: "abcdef1234567890"}),
		"0.4.1-78-g1be766a", "1be766a", "2026-08-31")
	if ver != "0.4.1-78-g1be766a" {
		t.Errorf("version = %q, want the stamped one", ver)
	}
	if sha != "1be766a" || date != "2026-08-31" {
		t.Errorf("stamped commit/date were overwritten: %q %q", sha, date)
	}
}

// A build from a working tree names no release, so the placeholder stands —
// but the commit is still worth having, and an edited tree says so.
func TestFromBuildInfo_DevelBuildKeepsThePlaceholderAndFlagsDirt(t *testing.T) {
	ver, sha, _ := fromBuildInfo(bi("(devel)",
		debug.BuildSetting{Key: "vcs.revision", Value: "abcdef1234567890"},
		debug.BuildSetting{Key: "vcs.modified", Value: "true"},
	), defaultVersion, "", "")
	if ver != defaultVersion {
		t.Errorf("version = %q, want the placeholder for a devel build", ver)
	}
	if sha != "abcdef1-dirty" {
		t.Errorf("commit = %q, want abcdef1-dirty", sha)
	}
}

func TestFromBuildInfo_CleanTreeIsNotMarkedDirty(t *testing.T) {
	_, sha, _ := fromBuildInfo(bi("(devel)",
		debug.BuildSetting{Key: "vcs.revision", Value: "abcdef1234567890"},
		debug.BuildSetting{Key: "vcs.modified", Value: "false"},
	), defaultVersion, "", "")
	if sha != "abcdef1" {
		t.Errorf("commit = %q, want abcdef1", sha)
	}
}
