package allowlist

import (
	"slices"
	"strings"
)

var sharedHosting = []string{
	"s3.amazonaws.com",
	"cloudfront.net",
	"vercel.app",
	"netlify.app",
	"github.io",
	"pages.dev",
	"workers.dev",
	"herokuapp.com",
	"appspot.com",
	"blob.core.windows.net",
	"storage.googleapis.com",
	"firebaseapp.com",
	"web.app",
	"ngrok.io",
	"ngrok-free.app",
}

func SharedHosting() []string {
	return slices.Clone(sharedHosting)
}

func isSharedHosting(domain string) bool {
	return slices.ContainsFunc(sharedHosting, func(suffix string) bool {
		return domain == suffix ||
			strings.HasSuffix(domain, "."+suffix) ||
			strings.HasSuffix(suffix, "."+domain)
	})
}
