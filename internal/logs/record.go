package logs

import (
	"log/slog"
	"time"
)

type Record interface {
	slog.LogValuer
	LogTime() time.Time
}
