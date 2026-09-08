//go:build !windows

package permissions

import "os"

func secure(path string, directory bool) error {
	if err := checkType(path, directory); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if directory {
		mode = 0o700
	}
	return os.Chmod(path, mode)
}
