package vmexec

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/tahardi/xena/internal/config"
)

var ErrMissingVMAddress = errors.New("missing vm address")

func Default() (*SSH, error) {
	vm, err := config.LoadVM(filepath.Join(config.RepoConfigDir(), "vm.yaml"))
	if err != nil {
		return nil, err
	}

	if vm.Network.VMAddress == "" {
		return nil, fmt.Errorf("checking vm config: %w", ErrMissingVMAddress)
	}

	return NewSSH(
		filepath.Join(config.ConfigDir(), "automation_ed25519"),
		filepath.Join(config.ConfigDir(), "known_hosts"),
		"dev",
		vm.Network.VMAddress,
	), nil
}
