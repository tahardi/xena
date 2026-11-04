package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type GCPKey struct {
	Cmd     Command
	Bin     string
	TempDir string
}

type gcpSecret struct {
	Key            json.RawMessage `json:"key"`
	ServiceAccount string          `json:"service_account"`
	Project        string          `json:"project"`
}

type gcpKeyFile struct {
	ClientEmail  string `json:"client_email"`
	PrivateKeyID string `json:"private_key_id"`
}

func (g GCPKey) Create(ctx context.Context, old []byte) ([]byte, error) {
	s, k, err := decodeGCP(old)
	if err != nil {
		return nil, err
	}

	var created []byte
	err = g.withKey(s.Key, func(dir string, env []string) error {
		path := filepath.Join(dir, "new.json")
		_, err := g.Cmd.Output(
			ctx,
			env,
			g.bin(),
			"iam",
			"service-accounts",
			"keys",
			"create",
			path,
			"--iam-account="+k.ClientEmail,
		)
		if err != nil {
			return fmt.Errorf("creating gcp key: %w", err)
		}

		created, err = os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading new gcp key: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	s.Key = created

	return json.Marshal(s)
}

func (g GCPKey) Revoke(ctx context.Context, old, current []byte) error {
	_, o, err := decodeGCP(old)
	if err != nil {
		return err
	}

	c, _, err := decodeGCP(current)
	if err != nil {
		return err
	}

	return g.withKey(c.Key, func(_ string, env []string) error {
		_, err := g.Cmd.Output(
			ctx,
			env,
			g.bin(),
			"iam",
			"service-accounts",
			"keys",
			"delete",
			o.PrivateKeyID,
			"--iam-account="+o.ClientEmail,
			"--quiet",
		)
		if err != nil {
			return fmt.Errorf("deleting gcp key %s: %w", o.PrivateKeyID, err)
		}

		return nil
	})
}

func (g GCPKey) Rejected(ctx context.Context, old []byte) (bool, error) {
	s, _, err := decodeGCP(old)
	if err != nil {
		return false, err
	}

	var rejected bool
	err = g.withKey(s.Key, func(_ string, env []string) error {
		_, err := g.Cmd.Output(ctx, env, g.bin(), "auth", "print-access-token")
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("checking old gcp key: %w", ctxErr)
		}

		rejected = err != nil

		return nil
	})

	return rejected, err
}

func (g GCPKey) withKey(key []byte, fn func(dir string, env []string) error) error {
	dir, err := os.MkdirTemp(g.TempDir, "xena-gcp-*")
	if err != nil {
		return fmt.Errorf("creating gcp temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	keyFile := filepath.Join(dir, "key.json")
	if err := os.WriteFile(keyFile, key, fileMode); err != nil {
		return fmt.Errorf("writing gcp key file: %w", err)
	}

	return fn(dir, []string{
		"CLOUDSDK_CONFIG=" + dir,
		"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=" + keyFile,
		"CLOUDSDK_CORE_DISABLE_PROMPTS=1",
	})
}

func (g GCPKey) bin() string {
	if g.Bin == "" {
		return "gcloud"
	}

	return g.Bin
}

func decodeGCP(data []byte) (gcpSecret, gcpKeyFile, error) {
	var s gcpSecret
	if err := json.Unmarshal(data, &s); err != nil {
		return gcpSecret{}, gcpKeyFile{}, fmt.Errorf("decoding gcp-grant secret: %w", err)
	}

	var k gcpKeyFile
	if err := json.Unmarshal(s.Key, &k); err != nil {
		return gcpSecret{}, gcpKeyFile{}, fmt.Errorf("decoding gcp-grant key: %w", err)
	}

	return s, k, nil
}
