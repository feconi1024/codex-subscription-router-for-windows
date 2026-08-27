//go:build windows

package main

import (
	"os"
	"testing"
)

func TestWindowsPlatformDefaults(t *testing.T) {
	if got := defaultRealExecutableName(); got != "codex.real.exe" {
		t.Fatalf("defaultRealExecutableName() = %q, want codex.real.exe", got)
	}
	signals := shutdownSignals()
	if len(signals) != 1 || signals[0] != os.Interrupt {
		t.Fatalf("shutdownSignals() = %#v, want only os.Interrupt", signals)
	}
}
