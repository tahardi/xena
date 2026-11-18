package config

import (
	"errors"
	"fmt"

	"go.yaml.in/yaml/v3"
)

var ErrFrontmatterNotMapping = errors.New("frontmatter is not a mapping")

func ParseFrontmatter(fields string) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(fields), &doc); err != nil {
		return nil, fmt.Errorf("parsing frontmatter: %w", err)
	}

	if len(doc.Content) == 0 {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, nil
	}

	if root := doc.Content[0]; len(doc.Content) == 1 && root.Kind == yaml.MappingNode {
		return root, nil
	}
	return nil, fmt.Errorf("parsing frontmatter: %w", ErrFrontmatterNotMapping)
}
