package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

var ErrIncompleteKey = errors.New("created key is missing fields")

type AWSKey struct {
	Cmd Command
	Bin string
}

type awsSecret struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	UserName        string `json:"user_name"`
	RoleARN         string `json:"role_arn"`
	Region          string `json:"region"`
}

func (a AWSKey) Create(ctx context.Context, old []byte) ([]byte, error) {
	s, err := decodeAWS(old)
	if err != nil {
		return nil, err
	}

	out, err := a.Cmd.Output(
		ctx,
		s.env(),
		a.bin(),
		"iam",
		"create-access-key",
		"--user-name",
		s.UserName,
		"--output",
		"json",
	)
	if err != nil {
		return nil, fmt.Errorf("creating aws access key: %w", err)
	}

	var created map[string]map[string]string
	if err := json.Unmarshal(out, &created); err != nil {
		return nil, fmt.Errorf("decoding aws access key: %w", err)
	}

	s.AccessKeyID = created["AccessKey"]["AccessKeyId"]
	s.SecretAccessKey = created["AccessKey"]["SecretAccessKey"]
	if s.AccessKeyID == "" || s.SecretAccessKey == "" {
		return nil, fmt.Errorf("decoding aws access key: %w", ErrIncompleteKey)
	}

	return json.Marshal(s)
}

func (a AWSKey) Revoke(ctx context.Context, old, current []byte) error {
	o, err := decodeAWS(old)
	if err != nil {
		return err
	}

	c, err := decodeAWS(current)
	if err != nil {
		return err
	}

	_, err = a.Cmd.Output(
		ctx,
		c.env(),
		a.bin(),
		"iam",
		"delete-access-key",
		"--user-name",
		o.UserName,
		"--access-key-id",
		o.AccessKeyID,
	)
	if err != nil {
		return fmt.Errorf("deleting aws access key %s: %w", o.AccessKeyID, err)
	}

	return nil
}

func (a AWSKey) Rejected(ctx context.Context, old []byte) (bool, error) {
	s, err := decodeAWS(old)
	if err != nil {
		return false, err
	}

	_, err = a.Cmd.Output(ctx, s.env(), a.bin(), "sts", "get-caller-identity")
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, fmt.Errorf("checking old aws key: %w", ctxErr)
	}

	return err != nil, nil
}

func (a AWSKey) bin() string {
	if a.Bin == "" {
		return "aws"
	}

	return a.Bin
}

func (s awsSecret) env() []string {
	return []string{
		"AWS_ACCESS_KEY_ID=" + s.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + s.SecretAccessKey,
		"AWS_SHARED_CREDENTIALS_FILE=/dev/null",
		"AWS_CONFIG_FILE=/dev/null",
	}
}

func decodeAWS(data []byte) (awsSecret, error) {
	var s awsSecret
	if err := json.Unmarshal(data, &s); err != nil {
		return awsSecret{}, fmt.Errorf("decoding aws-grant secret: %w", err)
	}

	return s, nil
}
