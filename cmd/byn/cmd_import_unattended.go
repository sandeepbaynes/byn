package main

import (
	"fmt"
	"os"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// runImportUnattended is `byn import --unattended`: it takes values an agent
// stored while the vault was locked — sealed under a key this machine holds —
// and re-seals them under the vault key, so the master password protects them
// like everything else. Nothing is read out of the vault: the daemon re-seals
// in place.
//
// It is also the fix for a grant that lists such a value and cannot open it
// (see `byn help unattended`), which is why the error paths that report that
// case print this command.
func runImportUnattended(names []string, scope cliScope, all, dryRun, pwStdin bool) int {
	if all && len(names) > 0 {
		fmt.Fprintln(os.Stderr, "Error: --all imports every unattended value; drop the names, or drop --all")
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	req := ipc.UnattendedImportReq{Scope: scope.ToIPC(), Names: names, All: all, DryRun: dryRun}
	var resp ipc.UnattendedImportResp
	if dryRun {
		if err := newClient(dir, scope.Vault).Call(ipc.OpUnattendedImport, req, &resp); err != nil {
			return handleCallError(err)
		}
		renderUnattendedImport(resp, true)
		return exitOK
	}
	rc := mutateWithAuthRetry(pwStdin, false, true, nil, func(pw []byte) error {
		r := req
		r.Password = pw
		return newClient(dir, scope.Vault).Call(ipc.OpUnattendedImport, r, &resp)
	})
	if rc != exitOK {
		return rc
	}
	renderUnattendedImport(resp, false)
	if len(resp.Imported) == 0 && len(resp.Skipped) > 0 {
		return exitErr
	}
	return exitOK
}

func renderUnattendedImport(resp ipc.UnattendedImportResp, dryRun bool) {
	verb := "Imported"
	if dryRun {
		verb = "Would import"
	}
	if len(resp.Imported) == 0 && len(resp.Skipped) == 0 {
		fmt.Fprintln(os.Stderr, "No unattended values here — everything is already protected by the master password.")
		return
	}
	for _, it := range resp.Imported {
		fmt.Printf("%s/%s %s\n", it.Project, it.Env, it.Name)
	}
	if len(resp.Imported) > 0 {
		fmt.Fprintf(os.Stderr, "%s %d value(s): now protected by the master password.\n", verb, len(resp.Imported))
	}
	for _, sk := range resp.Skipped {
		fmt.Fprintf(os.Stderr, "%s %s: %s\n", yellow("skipped"), sk.Name, sk.Reason)
	}
	if !dryRun && len(resp.Imported) > 0 {
		hintf("Grants that inject %s were re-sealed; the values reach every env that inherits them.",
			pluralThem(len(resp.Imported)))
	}
}

func pluralThem(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}
