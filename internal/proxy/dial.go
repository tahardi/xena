package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/tahardi/xena/internal/allowlist"
	"github.com/tahardi/xena/internal/logs"
	"github.com/tahardi/xena/internal/netrange"
)

var (
	ErrNoAddresses     = errors.New("no addresses")
	ErrRefusedAddress  = errors.New("refused address")
	ErrNoUpstreamDials = errors.New("no upstream dials")
)

type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type countingConn struct {
	net.Conn

	in, out atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.in.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.out.Add(int64(n))
	return n, err
}

func (c *countingConn) CloseWrite() error {
	closeWrite(c.Conn)
	return nil
}

func (s *Server) dialChecked(ctx context.Context, host string, port int) (*countingConn, string, error) {
	if port < 1 || port > maxPort {
		return nil, logs.DecisionRefusePort, fmt.Errorf("checking port %d: %w", port, allowlist.ErrInvalidPort)
	}

	addrs, err := s.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, logs.DecisionErrorResolve, fmt.Errorf("resolving host %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, logs.DecisionErrorResolve, fmt.Errorf("resolving host %s: %w", host, ErrNoAddresses)
	}

	for i, addr := range addrs {
		addrs[i] = addr.Unmap()
		if netrange.Refused(addrs[i]) {
			return nil, logs.DecisionRefuseAddress, fmt.Errorf("checking host %s: %w", host, ErrRefusedAddress)
		}
	}

	errs := []error{ErrNoUpstreamDials}
	for _, addr := range addrs {
		conn, err := s.dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, uint16(port)).String())
		if err == nil {
			return &countingConn{Conn: conn}, "", nil
		}
		errs = append(errs, err)
	}

	return nil, logs.DecisionErrorDial, fmt.Errorf("dialing upstream: %w", errors.Join(errs...))
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
