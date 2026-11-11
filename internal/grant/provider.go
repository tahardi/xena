package grant

import (
	"context"
	"time"
)

type Credential struct {
	Value     []byte
	ExpiresAt time.Time
}

type Provider interface {
	Name() string
	SecretName() string
	VMSecret() string
	Issue(ctx context.Context, issuing []byte, lifetime time.Duration, now time.Time) (Credential, error)
}
