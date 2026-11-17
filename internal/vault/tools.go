package vault

import "github.com/tahardi/xena/internal/logs"

var toolList = []map[string]any{
	{
		"name":        logs.ToolSearch,
		"description": "Search the in-scope vault notes.",
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
		"name":        logs.ToolGetNote,
		"description": "Read one in-scope vault note by its vault-relative path.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"path": map[string]any{"type": "string"}},
			"required":   []string{"path"},
		},
	},
	{
		"name":        logs.ToolWriteNote,
		"description": "Write one in-scope vault note. Every written note is marked source: xena-vm.",
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
