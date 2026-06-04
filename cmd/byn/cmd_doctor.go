// `byn doctor` — diagnostic battery. Runs daemon-side checks
// (vault enumeration, fingerprint, schema, audit chain) and surfaces
// per-check ok/warn/fail. Exit code is non-zero if any check failed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func runDoctor(args []string, _ cliScope) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	var resp ipc.DoctorResp
	if err := newClient(dir).Call(ipc.OpDoctor, ipc.DoctorReq{}, &resp); err != nil {
		return handleCallError(err)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return doctorExitCode(resp)
	}
	for _, c := range resp.Checks {
		var marker string
		switch c.Severity {
		case "ok":
			marker = "  OK   "
		case "warn":
			marker = " WARN  "
		case "fail":
			marker = " FAIL  "
		default:
			marker = " ?     "
		}
		if c.Detail != "" {
			fmt.Printf("[%s] %-40s  %s\n", marker, c.Name, c.Detail)
		} else {
			fmt.Printf("[%s] %s\n", marker, c.Name)
		}
	}
	return doctorExitCode(resp)
}

func doctorExitCode(r ipc.DoctorResp) int {
	for _, c := range r.Checks {
		if c.Severity == "fail" {
			return exitErr
		}
	}
	return exitOK
}
