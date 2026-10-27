package proxy

import (
	"log/slog"
	"net"
	"net/netip"
)

type sourceListener struct {
	net.Listener

	source netip.Addr
	logger *slog.Logger
}

func (l *sourceListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		remote, err := netip.ParseAddrPort(conn.RemoteAddr().String())
		if err == nil && remote.Addr().Unmap() == l.source {
			return conn, nil
		}

		l.logger.Warn("refusing connection", "remote", conn.RemoteAddr().String())
		_ = conn.Close()
	}
}
