package inventory

import (
	"bufio"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/tahardi/xena/internal/github"
)

const githubAppSettings = "https://github.com/settings/apps"

var ErrSameKey = errors.New("new github app key matches the stored key")

type GitHubAppKey struct {
	File           string
	AppID          int64
	InstallationID int64
	API            string
	HTTP           *http.Client
	Cmd            Command
	In             *bufio.Reader
	Out            io.Writer
}

func (g GitHubAppKey) Create(ctx context.Context, old []byte) ([]byte, error) {
	data, err := os.ReadFile(g.File)
	if err != nil {
		return nil, fmt.Errorf("reading new github app key: %w", err)
	}

	oldKey, err := github.ParseKey(old)
	if err != nil {
		return nil, fmt.Errorf("parsing old github app key: %w", err)
	}

	newKey, err := github.ParseKey(data)
	if err != nil {
		return nil, fmt.Errorf("parsing new github app key: %w", err)
	}

	if newKey.PublicKey.Equal(&oldKey.PublicKey) {
		return nil, fmt.Errorf("checking new github app key: %w", ErrSameKey)
	}

	tok, err := g.app(newKey).InstallationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking new github app key: %w", err)
	}

	if err := github.RevokeToken(ctx, g.API, tok.Value, g.HTTP); err != nil {
		return nil, fmt.Errorf("revoking check token: %w", err)
	}

	return data, nil
}

func (g GitHubAppKey) Revoke(ctx context.Context, old, _ []byte) error {
	oldKey, err := github.ParseKey(old)
	if err != nil {
		return fmt.Errorf("parsing old github app key: %w", err)
	}

	fp, err := github.Fingerprint(&oldKey.PublicKey)
	if err != nil {
		return err
	}

	if _, err := g.Cmd.Output(ctx, nil, "systemctl", "--user", "try-restart", "xena-tokend.service"); err != nil {
		return fmt.Errorf("restarting xena-tokend: %w", err)
	}

	_, err = fmt.Fprintf(
		g.Out,
		"Restarted xena-tokend; touch your YubiKey when it asks.\n"+
			"Delete the private key with fingerprint %s in the GitHub App settings (%s, your app, Private keys), "+
			"then press Enter.\n",
		fp,
		githubAppSettings,
	)
	if err != nil {
		return fmt.Errorf("prompting to delete old github app key: %w", err)
	}

	if _, err := g.In.ReadString('\n'); err != nil {
		return fmt.Errorf("waiting for old github app key delete: %w", err)
	}

	return nil
}

func (g GitHubAppKey) Rejected(ctx context.Context, old []byte) (bool, error) {
	oldKey, err := github.ParseKey(old)
	if err != nil {
		return false, fmt.Errorf("parsing old github app key: %w", err)
	}

	accepted, err := g.app(oldKey).KeyAccepted(ctx)
	if err != nil {
		return false, err
	}

	return !accepted, nil
}

func (g GitHubAppKey) app(key *rsa.PrivateKey) github.App {
	return github.App{
		ID:             g.AppID,
		InstallationID: g.InstallationID,
		Key:            key,
		API:            g.API,
		HTTP:           g.HTTP,
	}
}
