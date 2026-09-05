//go:build !linux && !darwin

package main

import "fmt"

func findBynExecProcs() []bynExecProc {
	fmt.Println("byn ps: process listing is not yet supported on this platform")
	return nil
}
