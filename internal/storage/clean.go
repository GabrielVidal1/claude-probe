package storage

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// QuietFor is how long a session must have been quiet before its scratch
// dir or a worktree it works in may be removed without --force.
var QuietFor = 30 * time.Minute

// Removal is what Remove did (or, dry, would do).
type Removal struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Freed  int64  `json:"freed"` // own bytes, as last measured
	Branch string `json:"branch,omitempty"`
	Note   string `json:"note,omitempty"`
	Dry    bool   `json:"dry,omitempty"`
}

// ErrUnsafe is returned when removing would lose work or pull a directory out
// from under a live session; --force overrides it.
var ErrUnsafe = errors.New("unsafe")

func unsafe(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUnsafe}, a...)...)
}

// isScratch says whether p is a session dir right under a scratch root
// (<root>/<encoded cwd>/<session uuid>) — the only shape Remove deletes
// with a plain rm.
func (s *Scanner) isScratch(p string) bool {
	if !uuidRE.MatchString(filepath.Base(p)) {
		return false
	}
	root := filepath.Dir(filepath.Dir(p))
	for _, r := range s.scratchRoots(Config{}) {
		if r == root {
			return true
		}
	}
	return false
}

// inUse finds a live process of ours whose cwd is inside p (Linux; elsewhere
// it says nothing).
func inUse(p string) int {
	if runtime.GOOS != "linux" {
		return 0
	}
	ents, _ := os.ReadDir("/proc")
	pre := strings.TrimSuffix(p, "/") + "/"
	for _, e := range ents {
		pid := e.Name()
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}
		cwd, err := os.Readlink("/proc/" + pid + "/cwd")
		if err == nil && (cwd == p || strings.HasPrefix(cwd, pre)) {
			var n int
			fmt.Sscanf(pid, "%d", &n)
			if n != os.Getpid() {
				return n
			}
		}
	}
	return 0
}

// Remove deletes one tracked item — a session's scratch dir or a git
// worktree — unless that would lose work or break a live session (then
// ErrUnsafe, unless force). A worktree goes through `git worktree remove`,
// and its branch is deleted when (and only when) it is merged. Transcripts
// and extra roots are never removed here.
func (s *Scanner) Remove(path string, force, dry bool) (Removal, error) {
	now := nowF()
	path = filepath.Clean(path)
	it := s.items[path]
	r := Removal{Path: path, Dry: dry}
	if it != nil {
		r.Kind, r.Freed = it.Kind, it.Own
	}
	quiet := func(sids ...string) error {
		if force {
			return nil
		}
		if t := s.lastTouch(sids...); t > 0 && now-t < QuietFor.Seconds() {
			return unsafe("a session using it was active %s ago", time.Duration((now-t)*1e9).Round(time.Second))
		}
		if pid := inUse(path); pid > 0 {
			return unsafe("process %d works in it", pid)
		}
		return nil
	}
	switch {
	case s.isScratch(path):
		r.Kind = "scratchpad"
		if err := quiet(filepath.Base(path)); err != nil {
			return r, err
		}
		if dry {
			return r, nil
		}
		if err := os.RemoveAll(path); err != nil {
			return r, err
		}
	case gitdirOf(path) != "":
		r.Kind = "worktree"
		admin := gitdirOf(path)
		common := commonOf(admin)
		g := readGit(path, admin, common, now)
		r.Branch = g.Branch
		sids := s.sessionsIn(path)
		if o, ok := s.origins[path]; ok {
			sids = append(sids, o.SessionID)
		}
		if err := quiet(sids...); err != nil {
			return r, err
		}
		if !force {
			if g.Dirty == nil || g.Merged == nil {
				return r, unsafe("can't tell what it holds")
			}
			if *g.Dirty > 0 {
				return r, unsafe("%d uncommitted change(s)", *g.Dirty)
			}
			if !*g.Merged {
				return r, unsafe("%d commit(s) not on %s", deref(g.Ahead), g.Base)
			}
		}
		if dry {
			return r, nil
		}
		args := []string{"worktree", "remove", path}
		if force {
			args = []string{"worktree", "remove", "--force", "--force", path}
		}
		if out, ok := gitOut(g.Repo, args...); !ok {
			return r, fmt.Errorf("git worktree remove: %s", out)
		}
		gitOut(g.Repo, "worktree", "prune")
		base := strings.TrimPrefix(g.Base, "origin/")
		if g.Branch != "" && g.Merged != nil && *g.Merged && g.Branch != base && g.Branch != "main" && g.Branch != "master" {
			if _, ok := gitOut(g.Repo, "branch", "-d", g.Branch); ok {
				r.Note = "branch " + g.Branch + " deleted (merged)"
			}
		} else if g.Branch != "" {
			r.Note = "branch " + g.Branch + " kept"
		}
	default:
		return r, fmt.Errorf("%s: not a session scratch dir or a git worktree", path)
	}
	if it != nil {
		s.gone(path, now)
	}
	return r, nil
}

func deref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func gitOut(dir string, args ...string) (string, bool) {
	return git(dir, args...)
}

// autoClean applies the clean policy: scratch dirs of sessions quiet for
// ScratchAfterDays (and the empty session dirs Claude Code leaves behind).
func (s *Scanner) autoClean(cfg Config, now float64) {
	after := cfg.Clean.ScratchAfterDays * 86400
	var freed int64
	n := 0
	for p, it := range s.items {
		if it.Kind != "scratchpad" {
			continue
		}
		last := math64max(s.lastTouch(it.SessionID), it.NewestAt)
		if now-last < after {
			continue
		}
		if r, err := s.Remove(p, false, false); err == nil {
			freed += r.Freed
			n++
		}
	}
	// the empty dirs: one per session that never wrote anything
	empties := 0
	for _, root := range s.scratchRoots(cfg) {
		projects, _ := os.ReadDir(root)
		for _, pr := range projects {
			pdir := filepath.Join(root, pr.Name())
			sessions, _ := os.ReadDir(pdir)
			left := len(sessions)
			for _, se := range sessions {
				dir := filepath.Join(pdir, se.Name())
				if !se.IsDir() || !uuidRE.MatchString(se.Name()) || !empty(dir) {
					continue
				}
				if now-math64max(s.lastTouch(se.Name()), mtime(dir)) < after {
					continue
				}
				if os.RemoveAll(dir) == nil {
					empties++
					left--
				}
			}
			if left == 0 {
				_ = os.Remove(pdir)
			}
		}
	}
	if n > 0 || empties > 0 {
		log.Printf("storage clean: %d scratch dir(s), %s freed; %d empty session dir(s)", n, human(freed), empties)
	}
}

func math64max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func human(n int64) string {
	f := float64(n)
	for _, u := range []string{"B", "KB", "MB", "GB"} {
		if f < 1000 {
			return fmt.Sprintf("%.0f %s", f, u)
		}
		f /= 1000
	}
	return fmt.Sprintf("%.1f TB", f)
}
