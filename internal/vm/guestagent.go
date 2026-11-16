package vm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
)

const (
	guestReadSize = 4096
	guestTailSize = 8192
	tailLines     = 40
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

type fileSeekArgs struct {
	Handle int    `json:"handle"`
	Offset int    `json:"offset"`
	Whence string `json:"whence"`
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

	out, err := m.virt.AgentCommand(ctx, m.config.Name, string(payload))
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(out), &agentReply{Return: result})
}

func (m *Machine) guestFileTail(ctx context.Context, path string) ([]string, error) {
	handle, err := m.openGuestFile(ctx, path)
	if err != nil {
		return nil, err
	}

	_ = m.agent(ctx, "guest-file-seek", fileSeekArgs{Handle: handle, Offset: -guestTailSize, Whence: "end"}, nil)

	var chunk fileChunk
	err = m.agent(ctx, "guest-file-read", fileHandleArgs{Handle: handle, Count: guestTailSize}, &chunk)
	closeErr := m.closeGuestFile(ctx, handle)
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(chunk.BufB64)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")

	return lines[max(0, len(lines)-tailLines):], closeErr
}
