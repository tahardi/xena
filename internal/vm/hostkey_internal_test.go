package vm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	hostKeyOpen = `{"execute":"guest-file-open",` +
		`"arguments":{"path":"/etc/ssh/ssh_host_ed25519_key.pub","mode":"r"}}`
	hostKeyRead  = `{"execute":"guest-file-read","arguments":{"handle":1002,"count":4096}}`
	hostKeyClose = `{"execute":"guest-file-close","arguments":{"handle":1002}}`
)

func agentCall(command string) string {
	return virsh + "qemu-agent-command xena-dev " + command
}

func agentRead(content string) string {
	return fmt.Sprintf(
		`{"return":{"count":%d,"buf-b64":%s,"eof":true}}`,
		len(content),
		strconv.Quote(base64.StdEncoding.EncodeToString([]byte(content))),
	)
}

func sshString(buf, value []byte) []byte {
	// Test key fields are a few dozen bytes, far below the uint32 limit.
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(value))) //nolint:gosec
	return append(buf, value...)
}

func ed25519Blob(t *testing.T, keyType string, extra []byte) string {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	blob := sshString(nil, []byte(keyType))
	blob = sshString(blob, append(pub, extra...))

	return base64.StdEncoding.EncodeToString(blob)
}

func hostKeyResponses(content string) []response {
	return []response{
		{Match: agentCall(hostKeyOpen), Out: `{"return":1002}`},
		{Match: agentCall(hostKeyRead), Out: agentRead(content)},
		{Match: agentCall(hostKeyClose), Out: `{"return":{}}`},
	}
}

func TestMachine_PinHostKey(t *testing.T) {
	good := ed25519Blob(t, "ssh-ed25519", nil)

	tests := []struct {
		name          string
		responses     []response
		wantCalls     []string
		wantKnown     string
		wantErr       error
		wantErrPrefix string
	}{
		{
			name:      "happy path - pins ed25519 key",
			responses: hostKeyResponses("ssh-ed25519 " + good + " root@xena-dev\n"),
			wantCalls: []string{agentCall(hostKeyOpen), agentCall(hostKeyRead), agentCall(hostKeyClose)},
			wantKnown: "192.168.150.10 ssh-ed25519 " + good + "\n",
		},
		{
			name:      "error - rsa key",
			responses: hostKeyResponses("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ root@xena-dev\n"),
			wantCalls: []string{agentCall(hostKeyOpen), agentCall(hostKeyRead), agentCall(hostKeyClose)},
			wantErr:   ErrHostKey,
		},
		{
			name:      "error - wrong blob length",
			responses: hostKeyResponses("ssh-ed25519 " + ed25519Blob(t, "ssh-ed25519", []byte{0}) + " root@xena-dev\n"),
			wantCalls: []string{agentCall(hostKeyOpen), agentCall(hostKeyRead), agentCall(hostKeyClose)},
			wantErr:   ErrHostKey,
		},
		{
			name: "error - invalid base64 buffer",
			responses: []response{
				{Match: agentCall(hostKeyOpen), Out: `{"return":1002}`},
				{Match: agentCall(hostKeyRead), Out: `{"return":{"count":3,"buf-b64":"!!!","eof":true}}`},
				{Match: agentCall(hostKeyClose), Out: `{"return":{}}`},
			},
			wantCalls:     []string{agentCall(hostKeyOpen), agentCall(hostKeyRead), agentCall(hostKeyClose)},
			wantErrPrefix: "reading host key: ",
		},
		{
			name:          "error - open fails",
			responses:     []response{{Match: agentCall(hostKeyOpen), Err: errFake}},
			wantCalls:     []string{agentCall(hostKeyOpen)},
			wantErrPrefix: "reading host key: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			fake := newFakeExec(t, tt.responses)
			m := newTestMachine(t, fake, &fakeSecrets{}, &fakeRotator{})

			// when
			err := m.PinHostKey(context.Background())

			// then
			requireErr(t, err, tt.wantErr, tt.wantErrPrefix)
			require.Equal(t, tt.wantCalls, fake.lines())

			if tt.wantKnown == "" {
				require.NoFileExists(t, m.knownHosts)
				return
			}

			got, readErr := os.ReadFile(m.knownHosts)
			require.NoError(t, readErr)
			require.Equal(t, tt.wantKnown, string(got))

			info, statErr := os.Stat(m.knownHosts)
			require.NoError(t, statErr)
			require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		})
	}
}
