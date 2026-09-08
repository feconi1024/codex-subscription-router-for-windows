// Package permissions protects Router-owned state, separately from the
// AppContainer read/execute permissions needed by the Desktop payload.
package permissions

import (
	"fmt"
	"os"
)

func Directory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return secure(path, true)
}

func File(path string) error { return secure(path, false) }

func checkType(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return fmt.Errorf("refusing to secure non-regular state path %q", path)
	}
	return nil
}
