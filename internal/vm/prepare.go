package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	preparedMaxAge = 7 * 24 * time.Hour
	preparedSize   = "20G"
)

func (m *Machine) prepareImage(ctx context.Context, base string, now time.Time) (string, error) {
	data := NewSeedData(m.config, "", "", "", "", now)
	data.InstanceID = fmt.Sprintf("prepare-%d", now.Unix())

	seed, err := RenderPrepareSeed(data)
	if err != nil {
		return "", fmt.Errorf("preparing image: %w", err)
	}

	sum := sha256.Sum256([]byte(m.config.Image.SHA256 + string(seed.UserData)))
	name := "prepared-" + hex.EncodeToString(sum[:])[:imagePrefix] + ".qcow2"
	prepared := filepath.Join(filepath.Dir(base), name)

	if info, statErr := os.Stat(prepared); statErr == nil && now.Sub(info.ModTime()) < preparedMaxAge {
		m.logger.Info("reusing prepared image", "path", prepared)
		return prepared, nil
	}

	m.logger.Info("preparing base image", "path", prepared)

	if err = m.makePreparedImage(ctx, base, prepared, seed); err != nil {
		return "", fmt.Errorf("preparing image: %w", err)
	}

	return prepared, nil
}

func (m *Machine) prepareSeedPath() string {
	return filepath.Join(m.dir, "prepare-seed.iso")
}

func (m *Machine) makePreparedImage(ctx context.Context, base, prepared string, seed Seed) error {
	if err := removeMatches(filepath.Dir(prepared), "prepared-*.qcow2", "*.tmp"); err != nil {
		return fmt.Errorf("removing old prepared images: %w", err)
	}

	tmp := prepared + ".tmp"

	err := m.bootPreparedImage(ctx, base, tmp, seed)
	if err == nil {
		err = os.Rename(tmp, prepared)
	}

	if err != nil {
		return errors.Join(err, m.cleanupPrepare(context.WithoutCancel(ctx), tmp))
	}

	return removeIfExists(m.prepareSeedPath())
}

func (m *Machine) bootPreparedImage(ctx context.Context, base, tmp string, seed Seed) error {
	_, err := m.run(ctx, nil, "qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", base, tmp)
	if err != nil {
		return err
	}

	if err = os.Chmod(tmp, privateFile); err != nil {
		return err
	}

	if _, err = m.run(ctx, nil, "qemu-img", "resize", "-f", "qcow2", tmp, preparedSize); err != nil {
		return err
	}

	if err = m.writeSeedISO(ctx, seed, m.prepareSeedPath()); err != nil {
		return fmt.Errorf("making prepare seed iso: %w", err)
	}

	if err = m.defineDomain(ctx, tmp, m.prepareSeedPath(), false); err != nil {
		return err
	}

	if err = checkCut(); err != nil {
		return err
	}

	if err = m.virt.StartDomain(ctx, m.config.Name); err != nil {
		return fmt.Errorf("starting prepare vm: %w", err)
	}

	if err = m.WaitReady(ctx); err != nil {
		return err
	}

	if err = m.Stop(ctx); err != nil {
		return err
	}

	if err = m.virt.UndefineDomain(ctx, m.config.Name); err != nil {
		return fmt.Errorf("undefining prepare vm: %w", err)
	}

	return nil
}

func (m *Machine) cleanupPrepare(ctx context.Context, tmp string) error {
	return errors.Join(
		m.removePrepareDomain(ctx),
		removeIfExists(tmp),
		removeIfExists(m.prepareSeedPath()),
	)
}

func (m *Machine) removePrepareDomain(ctx context.Context) error {
	state, err := m.State(ctx)
	if err != nil {
		return err
	}

	if state != stateUndef && state != stateShutOff {
		if err = m.virt.DestroyDomain(ctx, m.config.Name); err != nil {
			return fmt.Errorf("destroying prepare vm: %w", err)
		}
	}

	if state != stateUndef {
		if err = m.virt.UndefineDomain(ctx, m.config.Name); err != nil {
			return fmt.Errorf("undefining prepare vm: %w", err)
		}
	}

	return nil
}

func removeMatches(dir string, patterns ...string) error {
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return err
		}

		for _, match := range matches {
			if err = removeIfExists(match); err != nil {
				return err
			}
		}
	}

	return nil
}
