package vm

import (
	"testing"

	"github.com/digitalocean/go-libvirt"
	"github.com/stretchr/testify/require"
)

func TestFormatUUID(t *testing.T) {
	// given
	uuid := libvirt.UUID{0x6f, 0x1c, 0x2d, 0x3e, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x01}

	// when
	got := formatUUID(uuid)

	// then
	require.Equal(t, "6f1c2d3e-0000-4000-8000-000000000001", got)
}
