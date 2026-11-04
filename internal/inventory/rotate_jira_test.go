package inventory_test

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/inventory"
)

func jiraServer(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/myself" && ok &&
			user == "bot@example.com" && pass == "new-token" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	return srv
}

func jiraSecret(site, token string) string {
	return "JIRA_SITE=" + site + "\nJIRA_EMAIL=bot@example.com\nJIRA_TOKEN=" + token + "\n"
}

func TestJiraToken_Create(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		hidden  string
		site    string
		wantErr error
	}{
		{name: "happy path - reads and checks new token", in: "new-token\n"},
		{name: "happy path - reads token without echo", hidden: "new-token"},
		{name: "error - new token rejected", in: "wrong-token\n", wantErr: inventory.ErrNewRejected},
		{name: "error - empty input", in: "", wantErr: inventory.ErrNewRejected},
		{name: "error - site not https", in: "new-token\n", site: "http://example.com", wantErr: inventory.ErrInsecureSite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			srv := jiraServer(t)
			var out bytes.Buffer
			tok := inventory.JiraToken{
				In:         bufio.NewReader(strings.NewReader(tt.in)),
				Out:        &out,
				HTTP:       srv.Client(),
				ExpiryDays: 45,
			}
			if tt.hidden != "" {
				tok.ReadHidden = func() ([]byte, error) { return []byte(tt.hidden), nil }
			}
			site := srv.URL
			if tt.site != "" {
				site = tt.site
			}

			// when
			got, err := tok.Create(context.Background(), []byte(jiraSecret(site, "old-token")))

			// then
			assert.Contains(t, out.String(), "https://id.atlassian.com/manage-profile/security/api-tokens")
			assert.Contains(t, out.String(), "with a 45-day expiry")
			assert.NotContains(t, out.String(), "old-token")
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.NotContains(t, err.Error(), "wrong-token")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, jiraSecret(srv.URL, "new-token"), string(got))
			assert.NotContains(t, out.String(), "new-token")
		})
	}
}

func TestJiraToken_Revoke(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{name: "happy path - waits for enter", in: "\n"},
		{name: "error - input closed", in: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			srv := jiraServer(t)
			var out bytes.Buffer
			tok := inventory.JiraToken{In: bufio.NewReader(strings.NewReader(tt.in)), Out: &out, HTTP: srv.Client()}

			// when
			err := tok.Revoke(
				context.Background(),
				[]byte(jiraSecret(srv.URL, "old-token")),
				[]byte(jiraSecret(srv.URL, "new-token")),
			)

			// then
			assert.Contains(t, out.String(), "Revoke the old token")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestJiraToken_Rejected(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{name: "happy path - old token rejected", token: "old-token", want: true},
		{name: "happy path - token still accepted", token: "new-token", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			srv := jiraServer(t)
			tok := inventory.JiraToken{In: bufio.NewReader(strings.NewReader("")), Out: &bytes.Buffer{}, HTTP: srv.Client()}

			// when
			got, err := tok.Rejected(context.Background(), []byte(jiraSecret(srv.URL, tt.token)))

			// then
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
