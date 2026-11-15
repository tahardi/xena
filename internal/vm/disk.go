package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	diskMode    = 0o600
	stdinObject = "secret,id=sec0,file=/dev/stdin"
)

var (
	ErrDiskExists          = errors.New("disk exists")
	ErrInvalidSnapshotName = errors.New("invalid snapshot name")

	snapshotNamePattern = regexp.MustCompile(`^[a-z0-9-]+$`)
)

func (m *Machine) DiskPath() string {
	return filepath.Join(m.dir, m.config.Name+".qcow2")
}

func (m *Machine) CreateDisk(ctx context.Context, base string, key []byte) error {
	disk := m.DiskPath()
	if _, err := os.Stat(disk); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("creating disk: %w", ErrDiskExists)
	}

	if err := m.createDisk(ctx, base, key); err != nil {
		_ = os.Remove(disk)
		return fmt.Errorf("creating disk: %w", err)
	}

	return nil
}

func (m *Machine) createDisk(ctx context.Context, base string, key []byte) error {
	disk := m.DiskPath()

	_, err := m.run(
		ctx,
		bytes.NewReader(key),
		"qemu-img",
		"convert",
		"-f", "qcow2",
		"-O", "qcow2",
		"--object", stdinObject,
		"-o", "encrypt.format=luks,encrypt.key-secret=sec0",
		base,
		disk,
	)
	if err != nil {
		return err
	}

	if err = os.Chmod(disk, diskMode); err != nil {
		return err
	}

	_, err = m.run(
		ctx,
		bytes.NewReader(key),
		"qemu-img",
		"resize",
		"--object", stdinObject,
		"--image-opts", m.imageOpts(),
		strconv.Itoa(m.config.DiskGiB)+"G",
	)

	return err
}

func (m *Machine) Snapshot(ctx context.Context, name string) error {
	if err := m.snapshot(ctx, "-c", name); err != nil {
		return fmt.Errorf("taking snapshot %s: %w", name, err)
	}

	return nil
}

func (m *Machine) Restore(ctx context.Context, name string) error {
	if err := m.snapshot(ctx, "-a", name); err != nil {
		return fmt.Errorf("restoring snapshot %s: %w", name, err)
	}

	if err := m.rotator.RotateVMTokens(ctx); err != nil {
		return fmt.Errorf("rotating vm tokens: %w", err)
	}

	return nil
}

func (m *Machine) snapshot(ctx context.Context, flag, name string) error {
	if !snapshotNamePattern.MatchString(name) {
		return ErrInvalidSnapshotName
	}

	state, err := m.State(ctx)
	if err != nil {
		return fmt.Errorf("checking vm state: %w", err)
	}

	if state != stateShutOff && state != stateUndef {
		return fmt.Errorf("checking vm state: %w", ErrRunning)
	}

	key, err := m.secrets.Get(ctx, diskKeyName)
	if err != nil {
		return fmt.Errorf("reading disk key: %w", err)
	}
	defer clear(key)

	_, err = m.run(
		ctx,
		bytes.NewReader(key),
		"qemu-img",
		"snapshot",
		flag, name,
		"--object", stdinObject,
		"--image-opts", m.imageOpts(),
	)

	return err
}

func (m *Machine) imageOpts() string {
	return "driver=qcow2,file.filename=" + strings.ReplaceAll(m.DiskPath(), ",", ",,") + ",encrypt.key-secret=sec0"
}
