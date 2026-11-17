package vault

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/tahardi/xena/internal/logs"
)

const (
	MaxMessage = 64 * 1024

	initialBuffer = 4096

	maxQueryBytes   = 512
	maxLogPathBytes = 256
	maxLogToolBytes = 64
	defaultLimit    = 10
	maxLimit        = 20
	overFetch       = 5
	maxFetch        = 100
	defaultProtocol = "2025-06-18"

	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeRateLimited    = -32000
)

var (
	supportedProtocols = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
	errPathMismatch    = errors.New("path mismatch")
	errPeerUID         = errors.New("peer uid differs")
)

type recordWriter interface {
	Write(record logs.Record) error
}

type Server struct {
	Policy  *Policy
	Notes   Notes
	Log     recordWriter
	Limit   *Bucket
	Now     func() time.Time
	Version string

	writeMu sync.Mutex
}

type request struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content []textContent `json:"content"`
	IsError bool          `json:"isError"`
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()

	for {
		conn, err := ln.Accept()
		if ctx.Err() != nil {
			return nil
		}

		if err != nil {
			return fmt.Errorf("accepting connection: %w", err)
		}

		if unixConn, ok := conn.(*net.UnixConn); ok {
			if err := checkPeer(unixConn); err != nil {
				slog.Warn("refusing connection", "error", err)
				conn.Close()
				continue
			}
		}

		go s.Handle(ctx, conn)
	}
}

func (s *Server) Handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, initialBuffer), MaxMessage+1)

	for scanner.Scan() {
		reply := s.dispatch(ctx, scanner.Bytes())
		if reply != nil && s.reply(conn, *reply) != nil {
			return
		}
	}

	if errors.Is(scanner.Err(), bufio.ErrTooLong) {
		s.log("", "", logs.DecisionRefuseSize)
		_ = s.reply(conn, errorReply(nil, codeInvalidRequest, "message too large"))
	}
}

func (s *Server) dispatch(ctx context.Context, line []byte) *response {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		reply := errorReply(nil, codeParse, "parse error")
		return &reply
	}

	if len(req.ID) == 0 {
		return nil
	}

	var reply response
	switch {
	case req.Method == "tools/call":
		reply = resultReply(req.ID, s.callTool(ctx, req.Params))
	case !s.Limit.Allow():
		s.log("", "", logs.DecisionRefuseRate)
		reply = errorReply(req.ID, codeRateLimited, "rate limited")
	case req.Method == "initialize":
		reply = resultReply(req.ID, s.initialize(req.Params))
	case req.Method == "ping":
		reply = resultReply(req.ID, map[string]any{})
	case req.Method == "tools/list":
		reply = resultReply(req.ID, map[string]any{"tools": toolList})
	default:
		reply = errorReply(req.ID, codeMethodNotFound, "method not found")
	}
	return &reply
}

func (s *Server) initialize(params json.RawMessage) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)

	version := defaultProtocol
	if slices.Contains(supportedProtocols, p.ProtocolVersion) {
		version = p.ProtocolVersion
	}

	return map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": "xena-vault", "version": s.Version},
	}
}

func (s *Server) callTool(ctx context.Context, params json.RawMessage) toolResult {
	var call toolCall
	callErr := json.Unmarshal(params, &call)

	if len(call.Arguments) == 0 {
		call.Arguments = json.RawMessage("{}")
	}

	var target struct {
		Path string `json:"path"`
	}
	_ = json.Unmarshal(call.Arguments, &target)

	if !s.Limit.Allow() {
		return s.refuse(call.Name, target.Path, logs.DecisionRefuseRate)
	}

	if callErr != nil {
		return s.refuse("", "", logs.DecisionRefuseScope)
	}

	switch call.Name {
	case logs.ToolSearch:
		return s.search(ctx, call.Arguments)
	case logs.ToolGetNote:
		return s.getNote(ctx, call.Arguments)
	case logs.ToolWriteNote:
		return s.writeNote(ctx, call.Arguments)
	default:
		return s.refuse(call.Name, "", logs.DecisionRefuseScope)
	}
}

func (s *Server) search(ctx context.Context, raw json.RawMessage) toolResult {
	var args struct {
		Query *string `json:"query"`
		Limit *int    `json:"limit"`
	}
	if json.Unmarshal(raw, &args) != nil || args.Query == nil || len(*args.Query) > maxQueryBytes {
		return s.refuse(logs.ToolSearch, "", logs.DecisionRefuseScope)
	}

	limit := defaultLimit
	if args.Limit != nil {
		limit = *args.Limit
	}

	if limit < 1 || limit > maxLimit {
		return s.refuse(logs.ToolSearch, "", logs.DecisionRefuseScope)
	}

	s.log(logs.ToolSearch, "", logs.DecisionAllow)

	results, err := s.Notes.Search(ctx, *args.Query, min(limit*overFetch, maxFetch))
	if err != nil {
		return textResult("anchorhold failed", true)
	}

	kept := FilterResults(s.Policy, results, func(r SearchResult) string { return r.Path })
	return jsonResult(kept[:min(limit, len(kept))])
}

func (s *Server) getNote(ctx context.Context, raw json.RawMessage) toolResult {
	var args struct {
		Path *string `json:"path"`
	}
	if json.Unmarshal(raw, &args) != nil || args.Path == nil {
		return s.refuse(logs.ToolGetNote, "", logs.DecisionRefuseScope)
	}

	rel := *args.Path
	if err := s.Policy.CheckRead(rel); err != nil {
		return s.refuse(logs.ToolGetNote, rel, decision(err))
	}

	note, err := s.Notes.Get(ctx, rel)
	if err == nil && note.Path != rel {
		return s.refuse(logs.ToolGetNote, rel, decision(errPathMismatch))
	}

	s.log(logs.ToolGetNote, rel, logs.DecisionAllow)

	switch {
	case errors.Is(err, ErrNoteNotFound):
		return textResult("note not found", true)
	case err != nil:
		return textResult("anchorhold failed", true)
	default:
		return jsonResult(note)
	}
}

func (s *Server) writeNote(ctx context.Context, raw json.RawMessage) toolResult {
	var args struct {
		Path    *string `json:"path"`
		Content *string `json:"content"`
		Mode    *string `json:"mode"`
	}
	if json.Unmarshal(raw, &args) != nil || args.Path == nil || args.Content == nil {
		return s.refuse(logs.ToolWriteNote, "", logs.DecisionRefuseScope)
	}

	rel := *args.Path
	mode := modeCreate
	if args.Mode != nil {
		mode = *args.Mode
	}

	if mode != modeCreate && mode != modeOverwrite && mode != modeAppend {
		return s.refuse(logs.ToolWriteNote, rel, logs.DecisionRefuseScope)
	}

	if err := s.Policy.CheckWrite(rel); err != nil {
		return s.refuse(logs.ToolWriteNote, rel, decision(err))
	}

	s.log(logs.ToolWriteNote, rel, logs.DecisionAllow)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	content := *args.Content
	if mode == modeAppend {
		existing, err := os.ReadFile(filepath.Join(s.Policy.Root(), filepath.FromSlash(rel)))
		switch {
		case errors.Is(err, os.ErrNotExist):
			mode = modeCreate
		case err != nil:
			return textResult("anchorhold failed", true)
		default:
			content = joinAppend(string(existing), content)
			mode = modeOverwrite
		}
	}

	if err := s.Notes.Write(ctx, rel, WithSource(content), mode); err != nil {
		return textResult("anchorhold failed", true)
	}
	return textResult("written", false)
}

func (s *Server) refuse(tool, rel, decision string) toolResult {
	s.log(tool, rel, decision)
	return textResult("refused: "+decision, true)
}

func (s *Server) log(tool, rel, decision string) {
	entry := logs.GatewayEntry{
		Time:     s.Now(),
		Tool:     clip(tool, maxLogToolBytes),
		Path:     clip(rel, maxLogPathBytes),
		Decision: decision,
	}
	if err := s.Log.Write(entry); err != nil {
		slog.Error("writing gateway log", "error", err)
	}
}

func (s *Server) reply(conn net.Conn, reply response) error {
	line, err := json.Marshal(reply)
	if err != nil {
		return fmt.Errorf("encoding reply: %w", err)
	}

	if _, err := conn.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("writing reply: %w", err)
	}
	return nil
}

func decision(err error) string {
	switch {
	case err == nil:
		return logs.DecisionAllow
	case errors.Is(err, ErrTraversal):
		return logs.DecisionRefuseTraversal
	case errors.Is(err, ErrSymlink):
		return logs.DecisionRefuseSymlink
	case errors.Is(err, ErrAbsolute):
		return logs.DecisionRefuseAbsolute
	default:
		return logs.DecisionRefuseScope
	}
}

func checkPeer(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("reading peer: %w", err)
	}

	var cred *syscall.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return fmt.Errorf("reading peer: %w", err)
	}

	if credErr != nil {
		return fmt.Errorf("reading peer: %w", credErr)
	}

	if int(cred.Uid) != os.Getuid() {
		return errPeerUID
	}
	return nil
}

func joinAppend(existing, addition string) string {
	if existing == "" || strings.HasSuffix(existing, "\n") {
		return existing + addition
	}
	return existing + "\n" + addition
}

func clip(s string, limit int) string {
	if !utf8.ValidString(s) {
		return "<invalid>"
	}

	if len(s) <= limit {
		return s
	}

	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func resultReply(id json.RawMessage, result any) response {
	return response{JSONRPC: "2.0", ID: id, Result: result}
}

func errorReply(id json.RawMessage, code int, message string) response {
	if id == nil {
		id = json.RawMessage("null")
	}
	return response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}}
}

func textResult(text string, isError bool) toolResult {
	return toolResult{Content: []textContent{{Type: "text", Text: text}}, IsError: isError}
}

func jsonResult(value any) toolResult {
	data, err := json.Marshal(value)
	if err != nil {
		return textResult("encoding result failed", true)
	}
	return textResult(string(data), false)
}
