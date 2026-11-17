package vault

import (
	"encoding/json"

	"github.com/tahardi/xena/internal/logs"
)

var toolList = []map[string]any{
	{
		"name":        logs.ToolSearch,
		"description": "Search vault notes. Only hits in Projects/, Learning/Security/, and Ideas.md are returned.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string", "maxLength": maxQueryBytes},
				"limit": map[string]any{
					"type":    "integer",
					"minimum": 1,
					"maximum": maxLimit,
					"default": defaultLimit,
				},
			},
			"required": []string{"query"},
		},
	},
	{
		"name": logs.ToolGetNote,
		"description": "Read one note by its exact vault-relative path. Allowed: Projects/**/*.md, Learning/Security/<name>.md, and Ideas.md. " +
			"Any other path is refused and logged as a security alert.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"path": map[string]any{"type": "string"}},
			"required":   []string{"path"},
		},
	},
	{
		"name": logs.ToolWriteNote,
		"description": "Write one note by its exact vault-relative path. Allowed: Projects/**/*.md except Projects/Xena/Reports/, " +
			"Learning/Security/<name>.md, and Ideas.md. Any other path is refused and logged as a security alert. " +
			"Every written note is marked source: xena-vm.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path":    map[string]any{"type": "string"},
				"content": map[string]any{"type": "string"},
				"mode": map[string]any{
					"type":    "string",
					"enum":    []string{modeCreate, modeOverwrite, modeAppend},
					"default": modeCreate,
				},
			},
			"required": []string{"path", "content"},
		},
	},
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
