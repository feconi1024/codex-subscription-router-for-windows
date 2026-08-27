//go:build !windows

package main

import (
	"os"
	"syscall"
	"testing"
)

func TestUnixPlatformDefaults(t *testing.T) {
	if got := defaultRealExecutableName(); got != "codex.real" {
		t.Fatalf("defaultRealExecutableName() = %q, want codex.real", got)
	}
	signals := shutdownSignals()
	if len(signals) != 2 || signals[0] != os.Interrupt || signals[1] != syscall.SIGTERM {
		t.Fatalf("shutdownSignals() = %#v, want os.Interrupt and SIGTERM", signals)
	}
}
