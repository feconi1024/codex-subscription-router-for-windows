//go:build windows

package backend

import (
	"errors"
	"os"
	"strings"
)

// Windows has no portable os.Interrupt delivery to an arbitrary child. Phase
// 1 intentionally terminates the direct app-server child instead of managing
// a full descendant process tree; that tradeoff can be revisited after native
// integration testing.
func terminateProcess(process *os.Process) error {
	err := process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

// Windows environment variable names are case-insensitive.
func environmentEntryHasKey(entry, key string) bool {
	name, _, found := strings.Cut(entry, "=")
	return found && strings.EqualFold(name, key)
}
