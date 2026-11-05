package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// NudgeLine is what the UserPromptSubmit hook adds to the agent's context
// when a filesystem the session writes to is nearly full ("" otherwise): the
// session's scratch root (/tmp, often RAM) and its cwd's. Cheap — two
// statfs, and a bounded walk of the session's own scratch dir only when one
// is past the threshold.
func NudgeLine(sid, cwd, tmpDir string) string {
	at := LoadConfig().Nudge()
	if at <= 0 {
		return ""
	}
	root := fmt.Sprintf("/tmp/claude-%d", os.Getuid())
	if tmpDir != "" {
		root = filepath.Join(tmpDir, fmt.Sprintf("claude-%d", os.Getuid()))
	}
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	var lines []string
	seen := map[string]bool{}
	for _, p := range []string{root, cwd} {
		if p == "" {
			continue
		}
		fs, ok := FSOf(p)
		if !ok || fs.Total == 0 || seen[fs.Mount] {
			continue
		}
		seen[fs.Mount] = true
		used := 1 - float64(fs.Avail)/float64(fs.Total)
		if used < at {
			continue
		}
		what := fs.Mount
		if fs.RAM {
			what += " (a RAM tmpfs)"
		}
		line := fmt.Sprintf("%s is %.0f%% full, %s free", what, used*100, human(fs.Avail))
		if p == root && sid != "" {
			if dirs, _ := filepath.Glob(filepath.Join(root, "*", sid)); len(dirs) == 1 {
				old := MaxEntries
				MaxEntries = 50_000
				t := Walk(dirs[0], false, "")
				MaxEntries = old
				if t.Own >= 10<<20 {
					line += fmt.Sprintf("; your scratchpad holds %s (%s)", human(t.Own), dirs[0])
				}
			}
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return ""
	}
	return "[claude-probe] Disk nearly full: " + strings.Join(lines, "; ") +
		". Delete what you no longer need from your scratchpad, and write large downloads, builds and renders " +
		"to a directory on a roomier disk (or set TMPDIR there) — a full /tmp breaks every session's command output."
}
