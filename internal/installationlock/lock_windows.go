package installationlock

import (
	"os"
	"syscall"
	"unsafe"
)

func lock(file *os.File) (func(), error) {
	library := syscall.NewLazyDLL("kernel32.dll")
	var overlapped syscall.Overlapped
	result, _, err := library.NewProc("LockFileEx").Call(file.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if result == 0 {
		return nil, err
	}
	return func() { library.NewProc("UnlockFileEx").Call(file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlapped))) }, nil
}
