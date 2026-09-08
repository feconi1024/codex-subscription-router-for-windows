//go:build !windows

package installationlock

import (
	"os"
	"syscall"
)

func lock(file *os.File) (func(), error) {
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, err
	}
	return func() { syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }, nil
}
