package logs

import (
	"encoding/json"
	"time"
)

const (
	DecisionAllow           = "allow"
	DecisionAllowOnce       = "allow-once"
	DecisionAllowAlways     = "allow-always"
	DecisionDeny            = "deny"
	DecisionTimeout         = "timeout"
	DecisionRefuseIPLiteral = "refuse-ip-literal"
	DecisionRefuseAddress   = "refuse-address"
	DecisionRefusePort      = "refuse-port"
	DecisionErrorResolve    = "error-resolve"
	DecisionErrorDial       = "error-dial"
	DecisionRefuseScope     = "refuse-scope"
	DecisionRefuseTraversal = "refuse-traversal"
	DecisionRefuseSymlink   = "refuse-symlink"
	DecisionRefuseAbsolute  = "refuse-absolute"
	DecisionRefuseSize      = "refuse-size"
	DecisionRefuseRate      = "refuse-rate"
)

const (
	ToolSearch    = "search"
	ToolGetNote   = "get_note"
	ToolWriteNote = "write_note"
)

const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
)

type ProxyEntry struct {
	Time     time.Time `json:"time"`
	Host     string    `json:"host"`
	Port     int       `json:"port"`
	Decision string    `json:"decision"`
	BytesOut int64     `json:"bytes_out"`
	BytesIn  int64     `json:"bytes_in"`
}

type GatewayEntry struct {
	Time     time.Time `json:"time"`
	Tool     string    `json:"tool"`
	Path     string    `json:"path"`
	Decision string    `json:"decision"`
}

type Alert struct {
	Time     time.Time         `json:"time"`
	Rule     string            `json:"rule"`
	Severity string            `json:"severity"`
	Guard    bool              `json:"guard"`
	Entries  []json.RawMessage `json:"entries"`
}
