package vault

import "context"

type Notes interface {
	Search(ctx context.Context, query string, limit int) ([]SearchResult, error)
	Get(ctx context.Context, rel string) (Note, error)
	Write(ctx context.Context, rel, content, mode string) error
}

type SearchResult struct {
	Path    string `json:"path"`
	Title   string `json:"title"`
	Heading string `json:"heading"`
	Snippet string `json:"snippet"`
}

type Note struct {
	Path     string    `json:"path"`
	Title    string    `json:"title"`
	Tags     []string  `json:"tags"`
	Sections []Section `json:"sections"`
}

type Section struct {
	Heading string `json:"heading"`
	Text    string `json:"text"`
}
