// Package installationlock serializes launch admission with Python maintenance.
package installationlock

import (
	"os"
	"path/filepath"
)

func Acquire(root string) (func(), error) {
	file, err := os.OpenFile(filepath.Join(root, "maintenance.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if info, err := file.Stat(); err != nil {
		file.Close()
		return nil, err
	} else if info.Size() == 0 {
		if _, err := file.WriteAt([]byte{0}, 0); err != nil {
			file.Close()
			return nil, err
		}
	}
	unlock, err := lock(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	return func() { unlock(); file.Close() }, nil
}
