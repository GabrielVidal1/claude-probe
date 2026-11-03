// Package plan reads the Claude account's plan and its last official usage
// reading — what a turn mark records, since Claude Code's transcript keeps
// neither.
package plan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var keys = []string{"planDisplayName", "organizationType", "organizationRateLimitTier",
	"userRateLimitTier", "seatTier", "billingType", "hasExtraUsageEnabled", "organizationRole",
	"accountUuid"}

type cached struct {
	mtime time.Time
	plan  map[string]any
}

var (
	mu    sync.Mutex
	cache = map[string]cached{}
)

// ConfigDir is the account's Claude config dir (CLAUDE_CONFIG_DIR, else ~/.claude).
func ConfigDir(raw string) string {
	if raw != "" {
		return raw
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".claude")
}

func claudeJSON(configDir string) string {
	if configDir != "" {
		return filepath.Join(configDir, ".claude.json")
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".claude.json")
}

// Of returns the plan as Claude Code last fetched it (`.claude.json` →
// `oauthAccount`): display name, org type, rate-limit tier, extra usage.
func Of(configDir string) map[string]any {
	f := claudeJSON(configDir)
	st, err := os.Stat(f)
	if err != nil {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	if c, ok := cache[f]; ok && c.mtime.Equal(st.ModTime()) {
		return c.plan
	}
	var doc struct {
		OAuth map[string]any `json:"oauthAccount"`
	}
	var out map[string]any
	if raw, err := os.ReadFile(f); err == nil && json.Unmarshal(raw, &doc) == nil && doc.OAuth != nil {
		out = map[string]any{}
		for _, k := range keys {
			if v, ok := doc.OAuth[k]; ok && v != nil {
				out[k] = v
			}
		}
		if len(out) == 0 {
			out = nil
		}
	}
	cache[f] = cached{st.ModTime(), out}
	return out
}

// Windows turns the status line's `rate_limits` block into
// {name: {pct, resetsAt}}.
func Windows(rl map[string]any) map[string]any {
	out := map[string]any{}
	for name, w := range rl {
		m, ok := w.(map[string]any)
		if !ok || m["used_percentage"] == nil {
			continue
		}
		out[name] = map[string]any{"pct": m["used_percentage"], "resetsAt": m["resets_at"]}
	}
	return out
}

// FileReading is the reading a status line persisted to
// `<config>/usage-state/rate-limits.json` (a setup some hosts have).
func FileReading(configDir string) map[string]any {
	raw, err := os.ReadFile(filepath.Join(ConfigDir(configDir), "usage-state", "rate-limits.json"))
	if err != nil {
		return nil
	}
	var doc struct {
		UpdatedAt  any            `json:"updated_at"`
		RateLimits map[string]any `json:"rate_limits"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	w := Windows(doc.RateLimits)
	if len(w) == 0 {
		return nil
	}
	return map[string]any{"updatedAt": doc.UpdatedAt, "windows": w}
}
