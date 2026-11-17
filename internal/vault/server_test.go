package vault_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/logs"
	"github.com/tahardi/xena/internal/vault"
)

var (
	errUnexpectedRecord = errors.New("unexpected record")
	errAnchorhold       = errors.New("stderr with secrets")
)

type writeCall struct {
	rel     string
	content string
	mode    string
}

type fakeNotes struct {
	mu          sync.Mutex
	results     []vault.SearchResult
	note        vault.Note
	getErr      error
	searchLimit int
	gets        []string
	writes      []writeCall
}

func (f *fakeNotes) Search(_ context.Context, _ string, limit int) ([]vault.SearchResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.searchLimit = limit
	return f.results, nil
}

func (f *fakeNotes) Get(_ context.Context, rel string) (vault.Note, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.gets = append(f.gets, rel)
	if f.getErr != nil {
		return vault.Note{}, f.getErr
	}

	note := f.note
	if note.Path == "" {
		note.Path = rel
	}
	return note, nil
}

func (f *fakeNotes) Write(_ context.Context, rel, content, mode string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.writes = append(f.writes, writeCall{rel: rel, content: content, mode: mode})
	return nil
}

type fakeLog struct {
	mu      sync.Mutex
	entries []logs.GatewayEntry
}

func (f *fakeLog) Write(record logs.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	entry, ok := record.(logs.GatewayEntry)
	if !ok {
		return errUnexpectedRecord
	}

	f.entries = append(f.entries, entry)
	return nil
}

func (f *fakeLog) decisions() []logs.GatewayEntry {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]logs.GatewayEntry, 0, len(f.entries))
	for _, e := range f.entries {
		out = append(out, logs.GatewayEntry{Tool: e.Tool, Path: e.Path, Decision: e.Decision})
	}
	return out
}

type rpcReply struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type toolReply struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

type harness struct {
	notes  *fakeNotes
	log    *fakeLog
	client net.Conn
	reader *bufio.Reader
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	root := t.TempDir()
	files := map[string]string{
		"Projects/A.md": "---\ntitle: a\n---\nold",
		"Journal/x.md":  "private",
	}
	for rel, body := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o700))
		require.NoError(t, os.WriteFile(full, []byte(body), 0o600))
	}

	now := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	h := &harness{notes: &fakeNotes{}, log: &fakeLog{}}
	server := &vault.Server{
		Policy:  vault.NewPolicy(root),
		Notes:   h.notes,
		Log:     h.log,
		Limit:   vault.NewBucket(10, 10, clock),
		Now:     clock,
		Version: "v-test",
	}

	serverConn, client := net.Pipe()
	t.Cleanup(func() { client.Close() })
	go server.Handle(t.Context(), serverConn)

	h.client = client
	h.reader = bufio.NewReader(client)
	return h
}

func (h *harness) send(t *testing.T, line string) {
	t.Helper()

	_, err := h.client.Write([]byte(line + "\n"))
	require.NoError(t, err)
}

func (h *harness) read(t *testing.T) rpcReply {
	t.Helper()

	line, err := h.reader.ReadBytes('\n')
	require.NoError(t, err)

	var reply rpcReply
	require.NoError(t, json.Unmarshal(line, &reply))
	return reply
}

func (h *harness) call(t *testing.T, id int, method string, params any) rpcReply {
	t.Helper()

	request, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	require.NoError(t, err)

	h.send(t, string(request))
	return h.read(t)
}

func (h *harness) tool(t *testing.T, name string, args any) toolReply {
	t.Helper()

	reply := h.call(t, 1, "tools/call", map[string]any{"name": name, "arguments": args})
	require.Nil(t, reply.Error)

	var result toolReply
	require.NoError(t, json.Unmarshal(reply.Result, &result))
	require.Len(t, result.Content, 1)
	require.Equal(t, "text", result.Content[0].Type)
	return result
}

func entry(tool, path, decision string) logs.GatewayEntry {
	return logs.GatewayEntry{Tool: tool, Path: path, Decision: decision}
}

func TestServer_Handle(t *testing.T) {
	t.Run("happy path - initialize", func(t *testing.T) {
		// given
		h := newHarness(t)

		// when
		reply := h.call(t, 1, "initialize", map[string]any{"protocolVersion": "2025-06-18"})

		// then
		var result struct {
			ProtocolVersion string                     `json:"protocolVersion"`
			Capabilities    map[string]json.RawMessage `json:"capabilities"`
			ServerInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"serverInfo"`
		}
		require.NoError(t, json.Unmarshal(reply.Result, &result))
		require.JSONEq(t, "1", string(reply.ID))
		require.Equal(t, "2025-06-18", result.ProtocolVersion)
		require.Equal(t, "xena-vault", result.ServerInfo.Name)
		require.Equal(t, "v-test", result.ServerInfo.Version)
		require.Contains(t, result.Capabilities, "tools")
		require.Empty(t, h.log.decisions())
	})

	t.Run("happy path - initialize unknown version", func(t *testing.T) {
		// given
		h := newHarness(t)

		// when
		reply := h.call(t, 1, "initialize", map[string]any{"protocolVersion": "1999-01-01"})

		// then
		var result struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		require.NoError(t, json.Unmarshal(reply.Result, &result))
		require.Equal(t, "2025-06-18", result.ProtocolVersion)
	})

	t.Run("happy path - notification", func(t *testing.T) {
		// given
		h := newHarness(t)
		h.send(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)

		// when
		reply := h.call(t, 7, "ping", map[string]any{})

		// then
		require.JSONEq(t, "7", string(reply.ID))
		require.Nil(t, reply.Error)
	})

	t.Run("happy path - tools list", func(t *testing.T) {
		// given
		h := newHarness(t)

		// when
		reply := h.call(t, 1, "tools/list", map[string]any{})

		// then
		var result struct {
			Tools []struct {
				Name        string `json:"name"`
				InputSchema struct {
					Type string `json:"type"`
				} `json:"inputSchema"`
			} `json:"tools"`
		}
		require.NoError(t, json.Unmarshal(reply.Result, &result))
		require.Len(t, result.Tools, 3)

		names := make([]string, 0, len(result.Tools))
		for _, tool := range result.Tools {
			names = append(names, tool.Name)
			require.Equal(t, "object", tool.InputSchema.Type)
		}
		require.Equal(t, []string{"search", "get_note", "write_note"}, names)
	})

	t.Run("happy path - search filters", func(t *testing.T) {
		// given
		h := newHarness(t)
		h.notes.results = []vault.SearchResult{
			{Path: "Projects/A.md", Snippet: "a"},
			{Path: "Journal/x.md", Snippet: "private"},
			{Path: "Ideas.md", Snippet: "i"},
		}

		// when
		result := h.tool(t, "search", map[string]any{"query": "x", "limit": 10})

		// then
		var hits []vault.SearchResult
		require.False(t, result.IsError)
		require.NoError(t, json.Unmarshal([]byte(result.Content[0].Text), &hits))
		require.Equal(t, []vault.SearchResult{h.notes.results[0], h.notes.results[2]}, hits)
		require.Equal(t, 50, h.notes.searchLimit)
		require.Equal(t, []logs.GatewayEntry{entry("search", "", "allow")}, h.log.decisions())
	})

	t.Run("happy path - search limit", func(t *testing.T) {
		// given
		h := newHarness(t)
		h.notes.results = []vault.SearchResult{{Path: "Projects/A.md"}, {Path: "Ideas.md"}}

		// when
		result := h.tool(t, "search", map[string]any{"query": "x", "limit": 1})

		// then
		var hits []vault.SearchResult
		require.NoError(t, json.Unmarshal([]byte(result.Content[0].Text), &hits))
		require.Len(t, hits, 1)
		require.Equal(t, 5, h.notes.searchLimit)
	})

	t.Run("happy path - get", func(t *testing.T) {
		// given
		h := newHarness(t)
		h.notes.note = vault.Note{Path: "Projects/A.md", Title: "A", Sections: []vault.Section{{Text: "old"}}}

		// when
		result := h.tool(t, "get_note", map[string]any{"path": "Projects/A.md"})

		// then
		var note vault.Note
		require.False(t, result.IsError)
		require.NoError(t, json.Unmarshal([]byte(result.Content[0].Text), &note))
		require.Equal(t, h.notes.note, note)
		require.Equal(t, []logs.GatewayEntry{entry("get_note", "Projects/A.md", "allow")}, h.log.decisions())
	})

	refusals := []struct {
		name     string
		path     string
		decision string
	}{
		{name: "error - get out of scope", path: "Journal/x.md", decision: "refuse-scope"},
		{name: "error - get traversal", path: "Projects/../Journal/x.md", decision: "refuse-traversal"},
		{name: "error - get absolute", path: "/etc/passwd", decision: "refuse-absolute"},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			// given
			h := newHarness(t)

			// when
			result := h.tool(t, "get_note", map[string]any{"path": tt.path})

			// then
			require.True(t, result.IsError)
			require.Equal(t, "refused: "+tt.decision, result.Content[0].Text)
			require.Empty(t, h.notes.gets)
			require.Equal(t, []logs.GatewayEntry{entry("get_note", tt.path, tt.decision)}, h.log.decisions())
		})
	}

	t.Run("error - get suffix mismatch", func(t *testing.T) {
		// given
		h := newHarness(t)
		h.notes.note = vault.Note{Path: "Archive/Projects/A.md", Title: "secret"}

		// when
		result := h.tool(t, "get_note", map[string]any{"path": "Projects/A.md"})

		// then
		require.True(t, result.IsError)
		require.Equal(t, "refused: refuse-scope", result.Content[0].Text)
		require.Equal(t, []logs.GatewayEntry{entry("get_note", "Projects/A.md", "refuse-scope")}, h.log.decisions())
	})

	t.Run("error - get not found", func(t *testing.T) {
		// given
		h := newHarness(t)
		h.notes.getErr = vault.ErrNoteNotFound

		// when
		result := h.tool(t, "get_note", map[string]any{"path": "Projects/A.md"})

		// then
		require.True(t, result.IsError)
		require.Equal(t, "note not found", result.Content[0].Text)
		require.Equal(t, []logs.GatewayEntry{entry("get_note", "Projects/A.md", "allow")}, h.log.decisions())
	})

	t.Run("error - get anchorhold failed", func(t *testing.T) {
		// given
		h := newHarness(t)
		h.notes.getErr = errAnchorhold

		// when
		result := h.tool(t, "get_note", map[string]any{"path": "Projects/A.md"})

		// then
		require.True(t, result.IsError)
		require.Equal(t, "anchorhold failed", result.Content[0].Text)
	})

	writes := []struct {
		name string
		args map[string]any
		want writeCall
	}{
		{
			name: "happy path - write create",
			args: map[string]any{"path": "Projects/New.md", "content": "body"},
			want: writeCall{rel: "Projects/New.md", content: "---\nsource: xena-vm\n---\nbody", mode: "create"},
		},
		{
			name: "happy path - write overwrite",
			args: map[string]any{"path": "Projects/A.md", "content": "---\nsource: desktop\n---\nb", "mode": "overwrite"},
			want: writeCall{rel: "Projects/A.md", content: "---\nsource: xena-vm\n---\nb", mode: "overwrite"},
		},
		{
			name: "happy path - write append",
			args: map[string]any{"path": "Projects/A.md", "content": "new", "mode": "append"},
			want: writeCall{
				rel:     "Projects/A.md",
				content: "---\ntitle: a\nsource: xena-vm\n---\nold\nnew",
				mode:    "overwrite",
			},
		},
		{
			name: "happy path - write append missing",
			args: map[string]any{"path": "Projects/B.md", "content": "new", "mode": "append"},
			want: writeCall{rel: "Projects/B.md", content: "---\nsource: xena-vm\n---\nnew", mode: "create"},
		},
	}
	for _, tt := range writes {
		t.Run(tt.name, func(t *testing.T) {
			// given
			h := newHarness(t)

			// when
			result := h.tool(t, "write_note", tt.args)

			// then
			require.False(t, result.IsError)
			require.Equal(t, []writeCall{tt.want}, h.notes.writes)
			require.Equal(t, []logs.GatewayEntry{entry("write_note", tt.want.rel, "allow")}, h.log.decisions())
		})
	}

	t.Run("error - write reports", func(t *testing.T) {
		// given
		h := newHarness(t)
		path := "Projects/Xena/Reports/2026-W43.md"

		// when
		result := h.tool(t, "write_note", map[string]any{"path": path, "content": "x"})

		// then
		require.True(t, result.IsError)
		require.Equal(t, "refused: refuse-scope", result.Content[0].Text)
		require.Empty(t, h.notes.writes)
		require.Equal(t, []logs.GatewayEntry{entry("write_note", path, "refuse-scope")}, h.log.decisions())
	})

	t.Run("error - write unknown mode", func(t *testing.T) {
		// given
		h := newHarness(t)

		// when
		result := h.tool(t, "write_note", map[string]any{"path": "Projects/A.md", "content": "x", "mode": "delete"})

		// then
		require.True(t, result.IsError)
		require.Empty(t, h.notes.writes)
		require.Equal(t, []logs.GatewayEntry{entry("write_note", "Projects/A.md", "refuse-scope")}, h.log.decisions())
	})

	t.Run("error - oversize", func(t *testing.T) {
		// given
		h := newHarness(t)
		line := strings.Repeat("a", vault.MaxMessage+1) + "\n"
		go func() { _, _ = h.client.Write([]byte(line)) }()

		// when
		reply := h.read(t)

		// then
		require.Equal(t, -32600, reply.Error.Code)
		require.JSONEq(t, "null", string(reply.ID))
		require.Equal(t, []logs.GatewayEntry{entry("", "", "refuse-size")}, h.log.decisions())

		_, err := h.reader.ReadBytes('\n')
		require.Error(t, err)
	})

	t.Run("error - rate", func(t *testing.T) {
		// given
		h := newHarness(t)
		for range 10 {
			require.False(t, h.tool(t, "get_note", map[string]any{"path": "Projects/A.md"}).IsError)
		}

		// when
		result := h.tool(t, "get_note", map[string]any{"path": "Projects/A.md"})

		// then
		require.True(t, result.IsError)
		require.Equal(t, "refused: refuse-rate", result.Content[0].Text)

		want := make([]logs.GatewayEntry, 0, 11)
		for range 10 {
			want = append(want, entry("get_note", "Projects/A.md", "allow"))
		}
		want = append(want, entry("get_note", "Projects/A.md", "refuse-rate"))
		require.Equal(t, want, h.log.decisions())
	})

	t.Run("error - rate malformed calls", func(t *testing.T) {
		// given
		h := newHarness(t)
		for range 10 {
			h.send(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7}}`)
			h.read(t)
		}

		// when
		result := h.tool(t, "get_note", map[string]any{"path": "Projects/A.md"})

		// then
		require.Equal(t, "refused: refuse-rate", result.Content[0].Text)
		require.Empty(t, h.notes.gets)
	})

	t.Run("error - rate other method", func(t *testing.T) {
		// given
		h := newHarness(t)
		for range 10 {
			require.Nil(t, h.call(t, 1, "ping", map[string]any{}).Error)
		}

		// when
		reply := h.call(t, 1, "ping", map[string]any{})

		// then
		require.Equal(t, -32000, reply.Error.Code)
		require.Equal(t, "rate limited", reply.Error.Message)
		require.Equal(t, []logs.GatewayEntry{entry("", "", "refuse-rate")}, h.log.decisions())
	})

	t.Run("error - unknown method", func(t *testing.T) {
		// given
		h := newHarness(t)

		// when
		reply := h.call(t, 1, "resources/list", map[string]any{})

		// then
		require.Equal(t, -32601, reply.Error.Code)
	})

	t.Run("error - bad json", func(t *testing.T) {
		// given
		h := newHarness(t)

		// when
		h.send(t, `{"jsonrpc":`)
		reply := h.read(t)

		// then
		require.Equal(t, -32700, reply.Error.Code)
		require.JSONEq(t, "null", string(reply.ID))
	})

	t.Run("error - unknown tool", func(t *testing.T) {
		// given
		h := newHarness(t)
		name := "delete_" + strings.Repeat("x", 100)

		// when
		result := h.tool(t, name, map[string]any{})

		// then
		require.True(t, result.IsError)
		require.Equal(t, "refused: refuse-scope", result.Content[0].Text)
		require.Equal(t, []logs.GatewayEntry{entry(name[:64], "", "refuse-scope")}, h.log.decisions())
	})

	badArgs := []struct {
		name string
		tool string
		args map[string]any
	}{
		{name: "error - bad arguments", tool: "get_note", args: map[string]any{"path": 7}},
		{name: "error - search oversize query", tool: "search", args: map[string]any{"query": strings.Repeat("q", 513)}},
		{name: "error - search missing query", tool: "search", args: map[string]any{}},
		{name: "error - search limit too high", tool: "search", args: map[string]any{"query": "q", "limit": 21}},
		{name: "error - write missing content", tool: "write_note", args: map[string]any{"path": "Projects/A.md"}},
	}
	for _, tt := range badArgs {
		t.Run(tt.name, func(t *testing.T) {
			// given
			h := newHarness(t)

			// when
			result := h.tool(t, tt.tool, tt.args)

			// then
			require.True(t, result.IsError)
			require.Equal(t, "refused: refuse-scope", result.Content[0].Text)
			require.Len(t, h.log.decisions(), 1)
			require.Equal(t, tt.tool, h.log.decisions()[0].Tool)
			require.Equal(t, "refuse-scope", h.log.decisions()[0].Decision)
		})
	}

	t.Run("happy path - log path cut", func(t *testing.T) {
		// given
		h := newHarness(t)
		long := "Projects/" + strings.Repeat(strings.Repeat("a", 60)+"/", 5) + "n.md"

		// when
		h.tool(t, "get_note", map[string]any{"path": long})

		// then
		require.Equal(t, []logs.GatewayEntry{entry("get_note", long[:256], "allow")}, h.log.decisions())
	})

	t.Run("happy path - log never holds content", func(t *testing.T) {
		// given
		h := newHarness(t)

		// when
		h.tool(t, "write_note", map[string]any{"path": "Projects/New.md", "content": "made-up-content"})
		h.tool(t, "search", map[string]any{"query": "made-up-query"})

		// then
		h.log.mu.Lock()
		defer h.log.mu.Unlock()
		for _, e := range h.log.entries {
			line, err := json.Marshal(e)
			require.NoError(t, err)
			require.NotContains(t, string(line), "made-up-content")
			require.NotContains(t, string(line), "made-up-query")
		}
	})
}

func TestServer_Serve(t *testing.T) {
	// given
	socket := filepath.Join(t.TempDir(), "vault.sock")
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "unix", socket)
	require.NoError(t, err)

	now := func() time.Time { return time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC) }
	server := &vault.Server{
		Policy:  vault.NewPolicy(t.TempDir()),
		Notes:   &fakeNotes{},
		Log:     &fakeLog{},
		Limit:   vault.NewBucket(10, 10, now),
		Now:     now,
		Version: "v-test",
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, ln) }()

	// when
	var dialer net.Dialer
	conn, err := dialer.DialContext(t.Context(), "unix", socket)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"))
	require.NoError(t, err)
	line, err := bufio.NewReader(conn).ReadBytes('\n')

	// then
	require.NoError(t, err)
	require.Contains(t, string(line), `"xena-vault"`)

	cancel()
	require.NoError(t, <-done)
}
