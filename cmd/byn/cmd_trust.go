// `byn trust` — manage the TOFU trust store for `.byn` files.
//
//	byn trust [PATH]            Trust the .byn at PATH (default: CWD/.byn)
//	byn trust list              List trusted paths
//	byn untrust [PATH]          Revoke trust for PATH (default: CWD/.byn)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func runTrust(args []string, _ cliScope) int {
	if len(args) > 0 {
		switch args[0] {
		case "list", "ls":
			return runTrustList(args[1:])
		case "help", "--help", "-h":
			printTrustUsage(os.Stdout)
			return exitOK
		}
	}
	return runTrustAdd(args)
}

func runTrustAdd(args []string) int {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	path := defaultBynPath(fs)
	body, err := os.ReadFile(path) // #nosec G304 -- user-named
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	bynDir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	if err := addTrust(bynDir, path, body); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	abs := canonicalize(path)
	hintf("Trusted %s (sha256=%s).", abs, hashBynFile(body)[:12])
	return exitOK
}

func runUntrust(args []string, _ cliScope) int {
	fs := flag.NewFlagSet("untrust", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	path := defaultBynPath(fs)
	bynDir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	removed, err := removeTrust(bynDir, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	abs := canonicalize(path)
	if !removed {
		fmt.Fprintf(os.Stderr, "(%s was not trusted)\n", abs)
		return exitOK
	}
	hintf("Untrusted %s.", abs)
	return exitOK
}

func runTrustList(args []string) int {
	fs := flag.NewFlagSet("trust list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	bynDir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	ts, err := loadTrustStore(bynDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(ts.Records, "", "  ")
		fmt.Println(string(out))
		return exitOK
	}
	if len(ts.Records) == 0 {
		fmt.Fprintln(os.Stderr, "(no trusted .byn files)")
		return exitOK
	}
	for _, r := range ts.Records {
		fmt.Printf("%-12s  %s\n", r.SHA256[:12], r.Path)
	}
	return exitOK
}

func defaultBynPath(fs *flag.FlagSet) string {
	if fs.NArg() >= 1 {
		return fs.Arg(0)
	}
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, ".byn")
}

func printTrustUsage(w *os.File) {
	_, _ = fmt.Fprintln(w, `byn trust — manage TOFU trust for .byn files

Usage:
  byn trust [PATH]              Trust the .byn at PATH (default: ./.byn)
  byn trust list [--json]       List currently trusted paths
  byn untrust [PATH]            Revoke trust (default: ./.byn)`)
}
