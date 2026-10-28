package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func readJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", filepath.Base(path), err)
	}

	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("parsing %s: %w", filepath.Base(path), err)
	}
	return nil
}
