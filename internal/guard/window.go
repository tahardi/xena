package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/tahardi/xena/internal/config"
)

const (
	windowFile = "window.json"
	windowMode = 0o644
)

type Window struct {
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	VMAddr  string    `json:"vm_address"`
	Targets []string  `json:"targets"`
}

func WriteWindow(dir string, w Window) error {
	data, err := json.Marshal(w)
	if err != nil {
		return fmt.Errorf("writing guard window: %w", err)
	}

	if err := config.WriteAtomic(filepath.Join(dir, windowFile), data, windowMode); err != nil {
		return fmt.Errorf("writing guard window: %w", err)
	}

	return nil
}

func RemoveWindow(dir string) error {
	err := os.Remove(filepath.Join(dir, windowFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing guard window: %w", err)
	}

	return nil
}
