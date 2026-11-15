package vm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/tahardi/xena/internal/config"
)

const (
	hostKeyPath    = "/etc/ssh/ssh_host_ed25519_key.pub"
	hostKeyType    = "ssh-ed25519"
	hostKeyBlobLen = 51
	guestReadSize  = 4096
	knownHostsMode = 0o600
)

var (
	ErrHostKey = errors.New("invalid host key")

	hostKeyBlobPrefix = []byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20")
)

type agentCommand struct {
	Execute   string `json:"execute"`
	Arguments any    `json:"arguments,omitempty"`
}

type agentReply struct {
	Return any `json:"return"`
}

type fileOpenArgs struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type fileHandleArgs struct {
	Handle int `json:"handle"`
	Count  int `json:"count,omitempty"`
}

type fileChunk struct {
	// The guest agent protocol names this field buf-b64.
	BufB64 string `json:"buf-b64"` //nolint:tagliatelle
}

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

func (m *Machine) readGuestFile(ctx context.Context, path string) ([]byte, error) {
	handle, err := m.openGuestFile(ctx, path)
	if err != nil {
		return nil, err
	}

	var chunk fileChunk
	err = m.agent(ctx, "guest-file-read", fileHandleArgs{Handle: handle, Count: guestReadSize}, &chunk)
	closeErr := m.closeGuestFile(ctx, handle)
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(chunk.BufB64)
	if err != nil {
		return nil, err
	}

	return data, closeErr
}

func (m *Machine) openGuestFile(ctx context.Context, path string) (int, error) {
	var handle int
	err := m.agent(ctx, "guest-file-open", fileOpenArgs{Path: path, Mode: "r"}, &handle)

	return handle, err
}

func (m *Machine) closeGuestFile(ctx context.Context, handle int) error {
	return m.agent(ctx, "guest-file-close", fileHandleArgs{Handle: handle}, nil)
}

func (m *Machine) agent(ctx context.Context, execute string, args, result any) error {
	payload, err := json.Marshal(agentCommand{Execute: execute, Arguments: args})
	if err != nil {
		return err
	}

	out, err := m.virsh(ctx, nil, "qemu-agent-command", m.config.Name, string(payload))
	if err != nil {
		return err
	}

	return json.Unmarshal(out, &agentReply{Return: result})
}
