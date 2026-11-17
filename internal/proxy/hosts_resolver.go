package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultHostsPath = "/etc/hosts"
	minHostsFields   = 2
)

var ErrSpecialUseName = errors.New("resolving special-use name")

var specialUseDomains = []string{"test", "invalid", "localhost", "example"}

type HostsOnlyResolver struct {
	next      Resolver
	hostsPath string
}

func NewHostsOnlyResolver(next Resolver, hostsPath string) *HostsOnlyResolver {
	return &HostsOnlyResolver{next: next, hostsPath: filepath.Clean(hostsPath)}
}

func (r *HostsOnlyResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	if !isSpecialUse(name) {
		return r.next.LookupNetIP(ctx, network, host)
	}

	// The path comes from the caller at construction, never from the looked-up name.
	data, err := os.ReadFile(r.hostsPath) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("reading hosts file: %w", err)
	}

	addrs := hostsAddrs(string(data), name)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("looking up %s in %s: %w", name, r.hostsPath, ErrSpecialUseName)
	}
	return addrs, nil
}

func isSpecialUse(name string) bool {
	for _, domain := range specialUseDomains {
		if name == domain || strings.HasSuffix(name, "."+domain) {
			return true
		}
	}
	return false
}

func hostsAddrs(data, name string) []netip.Addr {
	var addrs []netip.Addr
	for line := range strings.Lines(data) {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) < minHostsFields {
			continue
		}

		addr, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}

		for _, alias := range fields[1:] {
			if strings.TrimSuffix(strings.ToLower(alias), ".") == name {
				addrs = append(addrs, addr)
				break
			}
		}
	}
	return addrs
}
