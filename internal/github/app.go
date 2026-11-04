package github

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	jwtBackdate   = 60 * time.Second
	jwtLifetime   = 9 * time.Minute
	jwtHeaderJSON = `{"alg":"RS256","typ":"JWT"}`
)

var (
	ErrInvalidKey       = errors.New("invalid app key")
	ErrUnexpectedStatus = errors.New("unexpected status")
	ErrInvalidToken     = errors.New("invalid installation token")
)

type App struct {
	ID             int64
	InstallationID int64
	Key            *rsa.PrivateKey
	API            string
	HTTP           *http.Client
}

type Token struct {
	Value     string
	ExpiresAt time.Time
}

type jwtClaims struct {
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Issuer    string `json:"iss"`
}

type tokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func ParseKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("parsing app key: %w", ErrInvalidKey)
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing app key: %w", ErrInvalidKey)
	}

	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parsing app key: %w", ErrInvalidKey)
	}

	return key, nil
}

func (a App) JWT(now time.Time) (string, error) {
	if a.Key == nil {
		return "", fmt.Errorf("signing app jwt: %w", ErrInvalidKey)
	}

	claims, err := json.Marshal(jwtClaims{
		IssuedAt:  now.Add(-jwtBackdate).Unix(),
		ExpiresAt: now.Add(jwtLifetime).Unix(),
		Issuer:    strconv.FormatInt(a.ID, 10),
	})
	if err != nil {
		return "", fmt.Errorf("encoding jwt claims: %w", err)
	}

	enc := base64.RawURLEncoding
	unsigned := enc.EncodeToString([]byte(jwtHeaderJSON)) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))

	sig, err := rsa.SignPKCS1v15(nil, a.Key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing app jwt: %w", err)
	}

	return unsigned + "." + enc.EncodeToString(sig), nil
}

func (a App) InstallationToken(ctx context.Context) (Token, error) {
	path := fmt.Sprintf("/app/installations/%d/access_tokens", a.InstallationID)
	resp, err := a.do(ctx, http.MethodPost, path)
	if err != nil {
		return Token{}, fmt.Errorf("requesting installation token: %w", err)
	}

	defer closeBody(resp)

	if resp.StatusCode != http.StatusCreated {
		return Token{}, fmt.Errorf("requesting installation token: %w: %d", ErrUnexpectedStatus, resp.StatusCode)
	}

	var body tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Token{}, fmt.Errorf("decoding installation token: %w", err)
	}

	if body.Token == "" || body.ExpiresAt.IsZero() {
		return Token{}, fmt.Errorf("checking installation token: %w", ErrInvalidToken)
	}

	return Token{Value: body.Token, ExpiresAt: body.ExpiresAt}, nil
}

func (a App) Suspend(ctx context.Context) error {
	path := fmt.Sprintf("/app/installations/%d/suspended", a.InstallationID)
	resp, err := a.do(ctx, http.MethodPut, path)
	if err != nil {
		return fmt.Errorf("suspending installation: %w", err)
	}

	defer closeBody(resp)

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("suspending installation: %w: %d", ErrUnexpectedStatus, resp.StatusCode)
	}

	return nil
}

func (a App) do(ctx context.Context, method, path string) (*http.Response, error) {
	jwt, err := a.JWT(time.Now())
	if err != nil {
		return nil, err
	}

	return send(ctx, a.HTTP, method, a.API+path, jwt)
}
