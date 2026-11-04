package inventory

import (
	"cmp"
	"errors"
	"fmt"
	"time"
)

var ErrInvalidSetting = errors.New("invalid inventory setting")

const (
	defaultWarnDays         = 14
	defaultJiraScript       = "~/.claude/skills/card/scripts/jira.py"
	defaultJiraProject      = "XENA"
	defaultRetryAttempts    = 6
	defaultRetryWaitSeconds = 10
)

type Settings struct {
	WarnDays         int    `yaml:"warn_days"`
	JiraScript       string `yaml:"jira_script"`
	JiraProject      string `yaml:"jira_project"`
	RetryAttempts    int    `yaml:"retry_attempts"`
	RetryWaitSeconds int    `yaml:"retry_wait_seconds"`
}

func (s Settings) RetryWait() time.Duration {
	return time.Duration(s.RetryWaitSeconds) * time.Second
}

func (s Settings) withDefaults() (Settings, error) {
	s.WarnDays = cmp.Or(s.WarnDays, defaultWarnDays)
	s.JiraScript = cmp.Or(s.JiraScript, defaultJiraScript)
	s.JiraProject = cmp.Or(s.JiraProject, defaultJiraProject)
	s.RetryAttempts = cmp.Or(s.RetryAttempts, defaultRetryAttempts)
	s.RetryWaitSeconds = cmp.Or(s.RetryWaitSeconds, defaultRetryWaitSeconds)

	checks := []struct {
		name string
		bad  bool
	}{
		{"warn_days", s.WarnDays < 0},
		{"retry_attempts", s.RetryAttempts < 1},
		{"retry_wait_seconds", s.RetryWaitSeconds < 0},
	}
	for _, c := range checks {
		if c.bad {
			return Settings{}, fmt.Errorf("checking settings: %w: %s", ErrInvalidSetting, c.name)
		}
	}

	return s, nil
}
