package proxy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"strconv"
)

const socketMode = 0o660

func ListenSocket(ctx context.Context, path, group string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("listening on socket %s: %w", path, err)
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening on socket %s: %w", path, err)
	}

	if err := setSocketOwner(path, group); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("listening on socket %s: %w", path, err)
	}
	return ln, nil
}

func setSocketOwner(path, group string) error {
	if err := os.Chmod(path, socketMode); err != nil {
		return fmt.Errorf("setting mode of %s: %w", path, err)
	}

	if group == "" {
		return nil
	}

	g, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("looking up group %s: %w", group, err)
	}

	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("parsing gid of group %s: %w", group, err)
	}

	if err := os.Chown(path, -1, gid); err != nil {
		return fmt.Errorf("setting group of %s: %w", path, err)
	}
	return nil
}
