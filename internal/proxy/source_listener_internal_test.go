package proxy

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const acceptTimeout = 5 * time.Second

func TestSourceListener_Accept(t *testing.T) {
	tests := []struct {
		name     string
		network  string
		source   netip.Addr
		survives bool
	}{
		{name: "happy path - unix peer", network: "unix", source: netip.Addr{}, survives: true},
		{
			name:     "happy path - matching tcp peer",
			network:  "tcp",
			source:   netip.MustParseAddr("127.0.0.1"),
			survives: true,
		},
		{
			name:     "error - wrong tcp peer",
			network:  "tcp",
			source:   netip.MustParseAddr("192.168.150.10"),
			survives: false,
		},
		{name: "error - tcp peer with zero source", network: "tcp", source: netip.Addr{}, survives: false},
		{
			name:     "error - unix peer with real source",
			network:  "unix",
			source:   netip.MustParseAddr("127.0.0.1"),
			survives: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			address := "127.0.0.1:0"
			if tt.network == "unix" {
				address = filepath.Join(t.TempDir(), "s.sock")
			}

			ln, err := (&net.ListenConfig{}).Listen(t.Context(), tt.network, address)
			require.NoError(t, err)
			defer ln.Close()

			listener := &sourceListener{Listener: ln, source: tt.source, logger: slog.New(slog.DiscardHandler)}

			// when
			client, err := (&net.Dialer{}).DialContext(t.Context(), tt.network, ln.Addr().String())
			require.NoError(t, err)
			defer client.Close()

			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}

				defer conn.Close()
				_, _ = conn.Write([]byte("ok"))
			}()

			require.NoError(t, client.SetReadDeadline(time.Now().Add(acceptTimeout)))
			got, err := io.ReadAll(client)

			// then
			if tt.survives {
				require.NoError(t, err)
				require.Equal(t, "ok", string(got))
				return
			}

			require.NoError(t, err)
			require.Empty(t, got)
		})
	}
}
