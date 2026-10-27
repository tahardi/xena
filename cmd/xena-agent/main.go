package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tahardi/xena/internal/agent"
)

func main() {
	os.Exit(run())
}

func run() int {
	home, err := os.UserHomeDir()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "finding home dir:", err)
		return 1
	}

	exe, err := os.Executable()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "finding agent path:", err)
		return 1
	}

	a := agent.NewAgent(
		home,
		filepath.Join(filepath.Dir(exe), "guard"),
		"/bin/bash",
		"/usr/bin/sqlite3",
		os.Stdin,
		os.Stdout,
		os.Stderr,
	)

	return a.Run(context.Background(), os.Getenv("SSH_ORIGINAL_COMMAND"))
}
