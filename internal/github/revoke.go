package github

import (
	"context"
	"fmt"
	"net/http"
)

func RevokeToken(ctx context.Context, api, token string, c *http.Client) error {
	resp, err := send(ctx, c, http.MethodDelete, api+"/installation/token", token)
	if err != nil {
		return fmt.Errorf("revoking token: %w", err)
	}

	defer closeBody(resp)

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("revoking token: %w: %d", ErrUnexpectedStatus, resp.StatusCode)
	}

	return nil
}
