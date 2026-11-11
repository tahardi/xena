package github

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

func Fingerprint(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("encoding app public key: %w", err)
	}

	sum := sha256.Sum256(der)

	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:]), nil
}
