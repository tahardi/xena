package xena

import "embed"

//go:embed vm/agent/xena-agent vm/cloud-init vm/guard
var VMFiles embed.FS
