package config

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

func LoadNode(
	path string,
	current int,
	migrate map[int]func(map[string]any) (map[string]any, error),
) (yaml.Node, error) {
	if _, err := Load[map[string]any](path, current, migrate); err != nil {
		return yaml.Node{}, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return yaml.Node{}, fmt.Errorf("reading %s: %w", path, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return yaml.Node{}, fmt.Errorf("parsing %s: %w", path, err)
	}

	return doc, nil
}
