package memory

import (
	"os"
	"path/filepath"
)

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	_, err = tmp.Write(data)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}

	if err != nil {
		return err
	}

	return os.Rename(tmp.Name(), path)
}
