package vault

import "strings"

const (
	fenceLine  = "---"
	sourceLine = "source: xena-vm"
)

func WithSource(content string) string {
	lines := strings.SplitAfter(content, "\n")
	if lines[0] != fenceLine+"\n" && lines[0] != fenceLine+"\r\n" {
		return fenceLine + "\n" + sourceLine + "\n" + fenceLine + "\n" + content
	}

	newline := strings.TrimPrefix(lines[0], fenceLine)

	for end := 1; end < len(lines); end++ {
		if strings.TrimRight(lines[end], "\r\n") != fenceLine {
			continue
		}

		kept := []string{lines[0]}
		for _, line := range lines[1:end] {
			if !strings.HasPrefix(strings.TrimSpace(line), "source:") {
				kept = append(kept, line)
			}
		}

		kept = append(kept, sourceLine+newline)
		return strings.Join(append(kept, lines[end:]...), "")
	}

	return fenceLine + "\n" + sourceLine + "\n" + fenceLine + "\n" + content
}
