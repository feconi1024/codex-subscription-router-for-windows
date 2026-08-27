//go:build windows

package main

import "os"

func defaultRealExecutableName() string {
	return "codex.real.exe"
}

// Windows supports os.Interrupt for console interrupt delivery, but does not
// provide the Unix SIGTERM behavior used by the macOS implementation.
func shutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
