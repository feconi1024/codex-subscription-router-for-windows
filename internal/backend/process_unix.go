//go:build !windows

package backend

import (
	"errors"
	"os"
	"strings"
)

// Unix keeps the existing graceful interrupt-based shutdown behavior.
func terminateProcess(process *os.Process) error {
	err := process.Signal(os.Interrupt)
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

func environmentEntryHasKey(entry, key string) bool {
	return strings.HasPrefix(entry, key+"=")
}
