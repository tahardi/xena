package logs

import (
	"encoding/json"
	"log/slog"
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

func (e ProxyEntry) LogTime() time.Time {
	return e.Time
}

func (e ProxyEntry) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("host", e.Host),
		slog.Int("port", e.Port),
		slog.String("decision", e.Decision),
		slog.Int64("bytes_out", e.BytesOut),
		slog.Int64("bytes_in", e.BytesIn),
	)
}

func (e GatewayEntry) LogTime() time.Time {
	return e.Time
}

func (e GatewayEntry) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("tool", e.Tool),
		slog.String("path", e.Path),
		slog.String("decision", e.Decision),
	)
}

func (a Alert) LogTime() time.Time {
	return a.Time
}

func (a Alert) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("rule", a.Rule),
		slog.String("severity", a.Severity),
		slog.Bool("guard", a.Guard),
		slog.Any("entries", a.Entries),
	)
}
