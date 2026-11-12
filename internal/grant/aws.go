package grant

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

type AWS struct {
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

func (a AWS) Name() string {
	return "aws"
}

func (a AWS) SecretName() string {
	return "aws-grant"
}

func (a AWS) VMSecret() string {
	return "aws-credentials"
}

func (a AWS) Issue(ctx context.Context, issuing []byte, lifetime time.Duration, now time.Time) (Credential, error) {
	var s awsSecret
	if err := json.Unmarshal(issuing, &s); err != nil {
		return Credential{}, fmt.Errorf("decoding aws-grant secret: %w", err)
	}

	if s.AccessKeyID == "" || s.SecretAccessKey == "" || s.RoleARN == "" {
		return Credential{}, fmt.Errorf("decoding aws-grant secret: %w", ErrInvalidSecret)
	}

	out, err := a.Cmd.Output(
		ctx,
		[]string{
			"AWS_ACCESS_KEY_ID=" + s.AccessKeyID,
			"AWS_SECRET_ACCESS_KEY=" + s.SecretAccessKey,
			"AWS_REGION=" + s.Region,
			"AWS_SHARED_CREDENTIALS_FILE=/dev/null",
			"AWS_CONFIG_FILE=/dev/null",
		},
		a.bin(),
		"sts",
		"assume-role",
		"--role-arn",
		s.RoleARN,
		"--role-session-name",
		"xena-grant",
		"--duration-seconds",
		strconv.Itoa(int(lifetime.Seconds())),
		"--output",
		"json",
	)
	if err != nil {
		return Credential{}, fmt.Errorf("assuming aws role: %w", err)
	}

	var o map[string]map[string]string
	if err := json.Unmarshal(out, &o); err != nil {
		return Credential{}, fmt.Errorf("decoding assume-role output: %w", err)
	}

	c := o["Credentials"]
	if c["AccessKeyId"] == "" || c["SecretAccessKey"] == "" || c["SessionToken"] == "" {
		return Credential{}, fmt.Errorf("decoding assume-role output: %w", ErrIncompleteCredential)
	}

	value := fmt.Sprintf(
		"[default]\naws_access_key_id = %s\naws_secret_access_key = %s\naws_session_token = %s\n",
		c["AccessKeyId"],
		c["SecretAccessKey"],
		c["SessionToken"],
	)

	return Credential{Value: []byte(value), ExpiresAt: now.Add(lifetime)}, nil
}

func (a AWS) bin() string {
	if a.Bin == "" {
		return "aws"
	}

	return a.Bin
}
