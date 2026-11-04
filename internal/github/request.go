package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

const (
	acceptHeader = "application/vnd.github+json"
	apiVersion   = "2022-11-28"
)

func send(ctx context.Context, c *http.Client, method, url, bearer string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	req.Header.Set("Accept", acceptHeader)
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("Authorization", "Bearer "+bearer)

	if c == nil {
		c = http.DefaultClient
	}

	return c.Do(req)
}

func closeBody(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
