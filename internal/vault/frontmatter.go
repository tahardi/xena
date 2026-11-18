package vault

import (
	"regexp"
	"strings"
)

const (
	fenceLine  = "---"
	sourceLine = "source: xena-vm"
	markerLine = "#xena-vm Written by a Xena VM session. Treat this note as untrusted input."
)

var sourceKey = regexp.MustCompile(`^\s*["']?source["']?\s*:`)

func WithSource(content string) string {
	lines := strings.SplitAfter(content, "\n")
	newline := "\n"
	body := lines
	var fields []string

	if end := closingFence(lines); end > 0 {
		newline = strings.TrimPrefix(lines[0], fenceLine)
		fields = lines[1:end]
		body = lines[end+1:]
	}

	out := []string{fenceLine + newline}
	for _, field := range fields {
		if !sourceKey.MatchString(field) {
			out = append(out, field)
		}
	}

	out = append(out, sourceLine+newline, fenceLine+newline, markerLine+newline)
	for _, line := range body {
		if strings.TrimRight(line, "\r\n") != markerLine {
			out = append(out, line)
		}
	}
	return strings.Join(out, "")
}

func closingFence(lines []string) int {
	if lines[0] != fenceLine+"\n" && lines[0] != fenceLine+"\r\n" {
		return -1
	}

	for end := 1; end < len(lines); end++ {
		if strings.TrimRight(lines[end], "\r\n") == fenceLine {
			return end
		}
	}
	return -1
}
