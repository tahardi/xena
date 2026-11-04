package inventory

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"
)

const (
	KindNearExpiry    = "near-expiry"
	KindOverdue       = "overdue"
	KindUncappedSpend = "uncapped-spend"
	KindUnlistedFound = "unlisted-found"
)

type Finding struct {
	Kind   string
	Token  string
	Detail string
}

var tokenFiles = []struct {
	path   string
	marker string
}{
	{path: ".aws/credentials"},
	{path: ".config/gcloud/application_default_credentials.json"},
	{path: ".config/gcloud/credentials.db"},
	{path: ".config/gh/hosts.yml", marker: "oauth_token"},
	{path: ".config/jira/env"},
	{path: ".docker/config.json", marker: `"auth"`},
	{path: ".git-credentials"},
	{path: ".netrc"},
	{path: ".npmrc", marker: "_authToken"},
	{path: ".pypirc", marker: "password"},
}

func Check(inv Inventory, found []string, now time.Time) []Finding {
	var out []Finding
	listed := map[string]bool{}
	for _, tok := range inv.Entries {
		listed[tok.Stored] = true

		if due, ok := tok.Due(); ok {
			detail := "due " + due.Format(time.DateOnly)
			switch {
			case due.Before(now):
				out = append(out, Finding{Kind: KindOverdue, Token: tok.Name, Detail: detail})
			case !due.After(now.AddDate(0, 0, inv.Settings.WarnDays)):
				out = append(out, Finding{Kind: KindNearExpiry, Token: tok.Name, Detail: detail})
			}
		}

		if tok.CanSpend && tok.SpendCap == "" {
			out = append(out, Finding{Kind: KindUncappedSpend, Token: tok.Name})
		}
	}

	for _, f := range found {
		if !listed[f] {
			out = append(out, Finding{Kind: KindUnlistedFound, Detail: f})
		}
	}

	slices.SortFunc(out, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Token, b.Token), cmp.Compare(a.Detail, b.Detail))
	})

	return out
}

func Found(secretNames []string, home string) ([]string, error) {
	out := []string{}
	for _, f := range tokenFiles {
		ok, err := hasToken(filepath.Join(home, f.path), f.marker)
		if err != nil {
			return nil, err
		}

		if ok {
			out = append(out, "file:~/"+f.path)
		}
	}

	for _, name := range secretNames {
		out = append(out, "secrets:"+name)
	}

	slices.Sort(out)

	return out, nil
}

func hasToken(path, marker string) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking %s: %w", path, err)
	}

	return bytes.Contains(data, []byte(marker)), nil
}
