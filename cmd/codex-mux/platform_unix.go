//go:build !windows

package main

import (
	"os"
	"syscall"
)

func defaultRealExecutableName() string {
	return "codex.real"
}

func shutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}
