package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

var (
	ErrVMIPv6 = errors.New("VM has IPv6")
	linkLocal = netip.MustParsePrefix("fe80::/10")
)

type ipNeighbor struct {
	Dst string `json:"dst"`
}

type ipLink struct {
	AddrInfo []struct {
		Local string `json:"local"`
	} `json:"addr_info"`
}

func bridgeIPv6(
	ctx context.Context,
	ip func(ctx context.Context, args ...string) ([]byte, error),
	bridge string,
) error {
	var neighbors []ipNeighbor
	if err := readIP(ctx, ip, &neighbors, "-6", "-j", "neigh", "show", "dev", bridge); err != nil {
		return err
	}

	if len(neighbors) > 0 {
		return fmt.Errorf("%w on %s: %s", ErrVMIPv6, bridge, neighbors[0].Dst)
	}

	var links []ipLink
	if err := readIP(ctx, ip, &links, "-6", "-j", "addr", "show", "dev", bridge); err != nil {
		return err
	}

	for _, link := range links {
		for _, info := range link.AddrInfo {
			addr, err := netip.ParseAddr(info.Local)
			if err != nil || !linkLocal.Contains(addr) {
				return fmt.Errorf("%w on %s: %s", ErrVMIPv6, bridge, info.Local)
			}
		}
	}

	return nil
}

func readIP(
	ctx context.Context,
	ip func(ctx context.Context, args ...string) ([]byte, error),
	v any,
	args ...string,
) error {
	out, err := ip(ctx, args...)
	if err != nil {
		if reason := bytes.TrimSpace(out); len(reason) > 0 {
			return fmt.Errorf("running ip %s: %w: %s", strings.Join(args, " "), err, reason)
		}

		return fmt.Errorf("running ip %s: %w", strings.Join(args, " "), err)
	}

	if len(bytes.TrimSpace(out)) == 0 {
		return nil
	}

	if err := json.Unmarshal(out, v); err != nil {
		return fmt.Errorf("parsing ip %s: %w", strings.Join(args, " "), err)
	}

	return nil
}
