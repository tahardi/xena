package xena

import "embed"

//go:embed vm/agent/xena-agent vm/cloud-init all:vm/guard
var VMFiles embed.FS
