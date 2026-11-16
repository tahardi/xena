package vm

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/tahardi/xena/internal/config"
)

const (
	hostKeyPath    = "/etc/ssh/ssh_host_ed25519_key.pub"
	hostKeyType    = "ssh-ed25519"
	hostKeyBlobLen = 51
	knownHostsMode = 0o600
)

var (
	ErrHostKey = errors.New("invalid host key")

	hostKeyBlobPrefix = []byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20")
)

func (m *Machine) PinHostKey(ctx context.Context) error {
	content, err := m.readGuestFile(ctx, hostKeyPath)
	if err != nil {
		return fmt.Errorf("reading host key: %w", err)
	}

	key, err := parseHostKey(content)
	if err != nil {
		return fmt.Errorf("pinning host key: %w", err)
	}

	line := m.config.Network.VMAddress + " " + hostKeyType + " " + key + "\n"
	if err = config.WriteAtomic(m.knownHosts, []byte(line), knownHostsMode); err != nil {
		return fmt.Errorf("pinning host key: %w", err)
	}

	return nil
}

func parseHostKey(content []byte) (string, error) {
	line, _, _ := strings.Cut(string(content), "\n")

	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != hostKeyType {
		return "", ErrHostKey
	}

	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(blob) != hostKeyBlobLen || !bytes.HasPrefix(blob, hostKeyBlobPrefix) {
		return "", ErrHostKey
	}

	return base64.StdEncoding.EncodeToString(blob), nil
}
