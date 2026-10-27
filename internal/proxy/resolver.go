package proxy

import (
	"context"
	"net/netip"
)

type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}
