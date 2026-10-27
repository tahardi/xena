package proxy

import (
	"net"
	"sync/atomic"
)

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

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
