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

	a := agent.Agent{
		Home:     home,
		GuardDir: filepath.Join(filepath.Dir(exe), "guard"),
		Bash:     "/bin/bash",
		SQLite:   "/usr/bin/sqlite3",
		Stdin:    os.Stdin,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
	}

	return a.Run(context.Background(), os.Getenv("SSH_ORIGINAL_COMMAND"))
}
