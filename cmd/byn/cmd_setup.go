package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

// runSetup provisions the _byn/_byn-exec service users and installs the
// prebuilt privileged spawn helper. Must run as root; idempotent.
func runSetup(_ []string) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, boldRed("Error:")+" byn setup must run as root")
		fmt.Fprintln(os.Stderr, yellow("Run:")+" "+cyan("sudo byn setup"))
		return exitErr
	}

	// Locate the prebuilt helper next to the running byn binary.
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s could not determine byn executable path: %v\n",
			boldRed("Error:"), err)
		return exitErr
	}
	srcHelper := filepath.Join(filepath.Dir(exe), "byn-exec-helper")
	if _, serr := os.Stat(srcHelper); os.IsNotExist(serr) {
		fmt.Fprintf(os.Stderr, "%s prebuilt byn-exec-helper not found next to byn (%s); reinstall byn\n",
			boldRed("Error:"), srcHelper)
		return exitErr
	}

	destPath := privsep.HelperDestPath()
	configPath := privsep.HelperConfigPath()

	run := func(cmd string, runArgs ...string) error {
		c := exec.Command(cmd, runArgs...) //nolint:gosec // commands are fixed strings supplied by the privsep package, not user input
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		return c.Run()
	}

	if err := privsep.Setup(run, srcHelper, destPath, configPath); err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}

	fmt.Println("privsep provisioned (_byn, _byn-exec); spawn helper installed")
	return exitOK
}
