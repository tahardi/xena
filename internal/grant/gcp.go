package grant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	MaxGCPLifetime = time.Hour
	keyFileMode    = 0o600
)

type GCP struct {
	Cmd     Command
	Bin     string
	TempDir string
}

type gcpSecret struct {
	Key            json.RawMessage `json:"key"`
	ServiceAccount string          `json:"service_account"`
	Project        string          `json:"project"`
}

func (g GCP) Name() string {
	return "gcp"
}

func (g GCP) SecretName() string {
	return "gcp-grant"
}

func (g GCP) VMSecret() string {
	return "gcp-token"
}

func (g GCP) Issue(ctx context.Context, issuing []byte, lifetime time.Duration, now time.Time) (Credential, error) {
	var s gcpSecret
	if err := json.Unmarshal(issuing, &s); err != nil {
		return Credential{}, fmt.Errorf("decoding gcp-grant secret: %w", err)
	}
	if len(s.Key) == 0 || s.ServiceAccount == "" {
		return Credential{}, fmt.Errorf("decoding gcp-grant secret: %w", ErrInvalidSecret)
	}

	capped := min(lifetime, MaxGCPLifetime)

	dir, err := os.MkdirTemp(g.TempDir, "xena-gcp-*")
	if err != nil {
		return Credential{}, fmt.Errorf("creating gcp temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	keyFile := filepath.Join(dir, "key.json")
	if err := os.WriteFile(keyFile, s.Key, keyFileMode); err != nil {
		return Credential{}, fmt.Errorf("writing gcp key file: %w", err)
	}

	out, err := g.Cmd.Output(
		ctx,
		[]string{
			"CLOUDSDK_CONFIG=" + dir,
			"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=" + keyFile,
			"CLOUDSDK_CORE_DISABLE_PROMPTS=1",
		},
		g.bin(),
		"auth",
		"print-access-token",
		"--impersonate-service-account="+s.ServiceAccount,
		"--lifetime="+strconv.Itoa(int(capped.Seconds())),
	)
	if err != nil {
		return Credential{}, fmt.Errorf("impersonating gcp service account: %w", err)
	}

	token := bytes.TrimSpace(out)
	if len(token) == 0 {
		return Credential{}, fmt.Errorf("impersonating gcp service account: %w", ErrEmptyToken)
	}

	return Credential{Value: token, ExpiresAt: now.Add(capped)}, nil
}

func (g GCP) bin() string {
	if g.Bin == "" {
		return "gcloud"
	}

	return g.Bin
}
