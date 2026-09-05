package main

// cmd_skill.go installs byn's Agent Skill — the instructions an AI coding agent
// reads to learn how to use byn correctly.
//
// The skill ships INSIDE the binary (internal/agentskill), so `byn skill
// install` writes the skill for the byn that is actually installed. There is no
// separate artifact to keep in step, and no way to end up with a skill
// describing a different version than the one on PATH.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sandeepbaynes/byn/internal/agentskill"
)

// skillHomeDir is the per-user agent skills directory, and skillProjectDir the
// per-project one. Both follow the layout Claude Code and the Agent Skills
// specification use: <root>/skills/<name>/SKILL.md, where the directory name
// must equal the skill's `name` field.
const (
	skillHomeRoot    = ".claude"
	skillSkillsDir   = "skills"
	skillDirMode     = 0o755
	skillFileMode    = 0o644
	skillProjectRoot = ".claude"
)

func runSkill(args []string, _ cliScope) int {
	if len(args) == 0 {
		return skillUsage(os.Stderr)
	}
	switch args[0] {
	case "install":
		return runSkillInstall(args[1:])
	case "show", "print":
		fmt.Print(agentskill.Render(version))
		return exitOK
	case "path":
		return runSkillPath(args[1:])
	case "help", "-h", "--help":
		fmt.Print(helpFor("skill"))
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "byn skill: unknown subcommand %q\n", args[0])
		return skillUsage(os.Stderr)
	}
}

func skillUsage(w io.Writer) int {
	fmt.Fprintln(w, "usage: byn skill install [--user | --repo | --dir DIR]")
	fmt.Fprintln(w, "       byn skill show")
	fmt.Fprintln(w, "       byn skill path [--user | --repo | --dir DIR]")
	return exitErr
}

// skillFlags parses the destination selection shared by install and path.
func skillFlags(name string, args []string) (dir string, code int) {
	fs := flag.NewFlagSet("skill "+name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	user := fs.Bool("user", false, "install for this user (~/.claude/skills)")
	// NOT --project: that is byn's global scope flag (--project NAME), and a
	// second meaning one flag away from it would be a trap for both.
	repo := fs.Bool("repo", false, "install into this repository (./.claude/skills)")
	custom := fs.String("dir", "", "install into DIR (the skills root, not the skill directory)")
	if err := parseFlags(fs, args); err != nil {
		return "", exitErr
	}
	if *user && *repo {
		fmt.Fprintln(os.Stderr, "byn skill: --user and --repo are mutually exclusive")
		return "", exitErr
	}
	switch {
	case *custom != "":
		return filepath.Join(*custom, agentskill.Name), exitOK
	case *repo:
		return filepath.Join(skillProjectRoot, skillSkillsDir, agentskill.Name), exitOK
	default:
		// User scope is the default because byn is installed machine-wide: a
		// tool available in every directory should not need re-installing per
		// repository. --repo is for committing it alongside a codebase.
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s cannot resolve your home directory: %v\n", boldRed("Error:"), err)
			return "", exitErr
		}
		return filepath.Join(home, skillHomeRoot, skillSkillsDir, agentskill.Name), exitOK
	}
}

func runSkillPath(args []string) int {
	dir, code := skillFlags("path", args)
	if code != exitOK {
		return code
	}
	fmt.Println(filepath.Join(dir, agentskill.FileName))
	return exitOK
}

func runSkillInstall(args []string) int {
	dir, code := skillFlags("install", args)
	if code != exitOK {
		return code
	}
	dest := filepath.Join(dir, agentskill.FileName)

	// What was there before, so the result can say whether this was an install
	// or an upgrade — the answer people actually want after a byn upgrade.
	previous := ""
	if old, err := os.ReadFile(dest); err == nil { //nolint:gosec // path built from a flag the caller chose
		previous = agentskill.VersionOf(string(old))
	}

	if err := os.MkdirAll(dir, skillDirMode); err != nil {
		fmt.Fprintf(os.Stderr, "%s creating %s: %v\n", boldRed("Error:"), dir, err)
		return exitErr
	}
	if err := os.WriteFile(dest, []byte(agentskill.Render(version)), skillFileMode); err != nil {
		fmt.Fprintf(os.Stderr, "%s writing %s: %v\n", boldRed("Error:"), dest, err)
		return exitErr
	}

	switch {
	case previous == "":
		fmt.Printf("%s %s\n", cyan("Installed"), dest)
	case previous == version:
		fmt.Printf("%s %s (already %s)\n", cyan("Refreshed"), dest, version)
	default:
		fmt.Printf("%s %s (%s → %s)\n", cyan("Updated"), dest, previous, version)
	}
	fmt.Fprintln(os.Stderr, dim("agents pick this up on their next session; re-run after every byn upgrade"))
	return exitOK
}

// installedSkillVersion reports the version of an installed skill and where it
// was found, checking the project directory before the user one — the same
// order an agent resolves them, so byn reports on the file that would actually
// be read. Returns "" when no skill is installed.
func installedSkillVersion() (ver, path string) {
	var candidates []string
	candidates = append(candidates,
		filepath.Join(skillProjectRoot, skillSkillsDir, agentskill.Name, agentskill.FileName))
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, skillHomeRoot, skillSkillsDir, agentskill.Name, agentskill.FileName))
	}
	for _, p := range candidates {
		body, err := os.ReadFile(p) //nolint:gosec // fixed, well-known agent skill locations
		if err != nil {
			continue
		}
		return agentskill.VersionOf(string(body)), p
	}
	return "", ""
}
