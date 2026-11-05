package storage

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/GabrielVidal1/claude-probe/internal/paths"
)

// Root is an extra directory to track: measured as one item (Label names
// it), or — Worktrees — a parent whose children are git worktrees (their
// repos then get listed like the ones the sessions' cwds lead to).
type Root struct {
	Path      string `json:"path"`
	Label     string `json:"label,omitempty"`
	Worktrees bool   `json:"worktrees,omitempty"`
}

// CleanPolicy is what the daemon removes by itself. Off unless set.
type CleanPolicy struct {
	// ScratchAfterDays: a session's scratch dir (scratchpad + task output)
	// once the session has been quiet this long. 0 = never.
	ScratchAfterDays float64 `json:"scratchAfterDays,omitempty"`
}

func (c CleanPolicy) On() bool { return c.ScratchAfterDays > 0 }

// Config is <state dir>/storage.json — read at every pass, so a change
// applies without restarting the daemon.
type Config struct {
	Roots []Root      `json:"roots,omitempty"`
	Clean CleanPolicy `json:"clean,omitempty"`
	// NudgeAt: when the filesystem under a session's scratchpad or cwd is
	// fuller than this (0.9 = 90 %), its next prompt carries one line saying
	// so — the agent then knows to clean up and not to write big files there.
	// 0 = the default (0.9); negative = off.
	NudgeAt float64 `json:"nudgeAt,omitempty"`
}

// Nudge is the fill level the hook warns from (0: never).
func (c Config) Nudge() float64 {
	switch {
	case c.NudgeAt < 0:
		return 0
	case c.NudgeAt == 0:
		return 0.9
	}
	return c.NudgeAt
}

func ConfigPath() string { return filepath.Join(paths.StateDir(), "storage.json") }

func LoadConfig() Config {
	var c Config
	raw, err := os.ReadFile(ConfigPath())
	if err == nil {
		_ = json.Unmarshal(raw, &c)
	}
	return c
}

func SaveConfig(c Config) error {
	if err := paths.Ensure(); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(c, "", "  ")
	tmp := ConfigPath() + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ConfigPath())
}
