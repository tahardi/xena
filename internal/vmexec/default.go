package vmexec

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/tahardi/xena/internal/config"
)

var ErrMissingVMAddress = errors.New("missing vm address")

func Default() (SSH, error) {
	vm, err := config.LoadVM(filepath.Join(config.RepoConfigDir(), "vm.yaml"))
	if err != nil {
		return SSH{}, err
	}

	if vm.Network.VMAddress == "" {
		return SSH{}, fmt.Errorf("checking vm config: %w", ErrMissingVMAddress)
	}

	return SSH{
		Key:        filepath.Join(config.ConfigDir(), "automation_ed25519"),
		KnownHosts: filepath.Join(config.ConfigDir(), "known_hosts"),
		User:       "dev",
		Addr:       vm.Network.VMAddress,
	}, nil
}
