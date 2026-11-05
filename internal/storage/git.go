package storage

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Git is what a worktree holds that its files don't say: where it comes
// from, and whether removing it would lose anything.
type Git struct {
	Repo    string  `json:"repo"`             // the main working tree
	Branch  string  `json:"branch,omitempty"` // "" on a detached HEAD
	Head    string  `json:"head,omitempty"`
	Base    string  `json:"base,omitempty"`   // what "merged" compares with
	Merged  *bool   `json:"merged,omitempty"` // every commit of it is on Base
	Ahead   *int    `json:"ahead,omitempty"`  // commits Base doesn't have
	Dirty   *int    `json:"dirty,omitempty"`  // modified + untracked paths
	Locked  bool    `json:"locked,omitempty"`
	Native  bool    `json:"native,omitempty"` // Claude Code's own (<repo>/.claude/worktrees/…)
	IdleFor int64   `json:"idleS,omitempty"`  // since its last commit/checkout
	At      float64 `json:"at"`               // when this was read
}

// commonDir finds the git dir shared by every worktree of the repo that
// contains path ("" if none): walks up to the nearest .git.
func commonDir(path string) string {
	for p := filepath.Clean(path); ; {
		g := filepath.Join(p, ".git")
		if fi, err := os.Stat(g); err == nil {
			if fi.IsDir() {
				return g
			}
			if admin := gitdirOf(p); admin != "" {
				return commonOf(admin)
			}
			return ""
		}
		parent := filepath.Dir(p)
		if parent == p {
			return ""
		}
		p = parent
	}
}

// gitdirOf reads a worktree's .git file: its admin dir (<common>/worktrees/<name>).
func gitdirOf(wt string) string {
	raw, err := os.ReadFile(filepath.Join(wt, ".git"))
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(line, "gitdir:") {
		return ""
	}
	d := strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
	if !filepath.IsAbs(d) {
		d = filepath.Join(wt, d)
	}
	return filepath.Clean(d)
}

func commonOf(admin string) string {
	raw, err := os.ReadFile(filepath.Join(admin, "commondir"))
	if err != nil {
		return filepath.Dir(filepath.Dir(admin)) // <common>/worktrees/<name>
	}
	c := strings.TrimSpace(string(raw))
	if !filepath.IsAbs(c) {
		c = filepath.Join(admin, c)
	}
	return filepath.Clean(c)
}

// worktreesOf lists the linked worktrees a repo knows (path → admin dir),
// the main working tree excluded. A worktree whose directory is gone is
// listed too: `git worktree prune` hasn't run.
func worktreesOf(common string) map[string]string {
	out := map[string]string{}
	ents, err := os.ReadDir(filepath.Join(common, "worktrees"))
	if err != nil {
		return out
	}
	for _, e := range ents {
		admin := filepath.Join(common, "worktrees", e.Name())
		raw, err := os.ReadFile(filepath.Join(admin, "gitdir"))
		if err != nil {
			continue
		}
		g := strings.TrimSpace(string(raw))
		if !filepath.IsAbs(g) {
			g = filepath.Join(admin, g)
		}
		out[filepath.Dir(filepath.Clean(g))] = admin
	}
	return out
}

func mainTree(common string) string {
	if filepath.Base(common) == ".git" {
		return filepath.Dir(common)
	}
	return common // a bare repo
}

func git(dir string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"--no-optional-locks", "-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C")
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err == nil
}

func mtime(p string) float64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return float64(fi.ModTime().UnixNano()) / 1e9
}

// activity is the last time the worktree's own HEAD moved (a commit,
// checkout or reset in it) — cheap, read before any git command.
func activity(admin string) float64 {
	return max(mtime(filepath.Join(admin, "HEAD")), mtime(filepath.Join(admin, "logs", "HEAD")),
		mtime(filepath.Join(admin, "index")))
}

var bases = []string{"main", "master", "origin/main", "origin/master"}

// readGit fills what git says about one worktree (never writes: no optional locks).
func readGit(wt, admin, common string, now float64) *Git {
	g := &Git{Repo: mainTree(common), At: now, Native: strings.Contains(wt, "/.claude/worktrees/")}
	if _, err := os.Stat(filepath.Join(admin, "locked")); err == nil {
		g.Locked = true
	}
	if a := activity(admin); a > 0 {
		g.IdleFor = int64(now - a)
	}
	if raw, err := os.ReadFile(filepath.Join(admin, "HEAD")); err == nil {
		h := strings.TrimSpace(string(raw))
		if strings.HasPrefix(h, "ref: refs/heads/") {
			g.Branch = strings.TrimPrefix(h, "ref: refs/heads/")
		}
	}
	head, ok := git(wt, "rev-parse", "HEAD")
	if !ok {
		return g
	}
	g.Head = head
	if s, ok := git(wt, "status", "--porcelain", "--untracked-files=normal"); ok {
		n := 0
		if s != "" {
			n = len(strings.Split(s, "\n"))
		}
		g.Dirty = &n
	}
	if ct, ok := git(wt, "log", "-1", "--format=%ct", "HEAD"); ok {
		if t, err := strconv.ParseFloat(ct, 64); err == nil && now-t < float64(g.IdleFor) {
			g.IdleFor = int64(now - t)
		}
	}
	for _, b := range bases {
		if _, ok := git(g.Repo, "rev-parse", "--verify", "-q", b); !ok {
			continue
		}
		if g.Base == "" {
			g.Base = b
		}
		if _, ok := git(g.Repo, "merge-base", "--is-ancestor", head, b); ok {
			t, z := true, 0
			g.Base, g.Merged, g.Ahead = b, &t, &z
			return g
		}
	}
	if g.Base != "" {
		f := false
		g.Merged = &f
		if n, ok := git(g.Repo, "rev-list", "--count", g.Base+".."+head); ok {
			if v, err := strconv.Atoi(n); err == nil {
				g.Ahead = &v
			}
		}
	}
	return g
}

// WorktreeOp reads `git worktree add|remove <path>` out of one process's
// argv: the operation and the worktree's absolute path ("" if it isn't one,
// or the path was relative and cwd unknown).
func WorktreeOp(argv []string, cwd string) (op, path string) {
	if len(argv) == 0 || filepath.Base(argv[0]) != "git" {
		return "", ""
	}
	dir := cwd
	i := 1
	for ; i < len(argv); i++ {
		a := argv[i]
		if a == "-C" && i+1 < len(argv) {
			i++
			if filepath.IsAbs(argv[i]) {
				dir = argv[i]
			} else if dir != "" {
				dir = filepath.Join(dir, argv[i])
			}
			continue
		}
		if (a == "-c" || a == "--git-dir" || a == "--work-tree") && i+1 < len(argv) {
			i++
			continue
		}
		if !strings.HasPrefix(a, "-") {
			break
		}
	}
	if i+1 >= len(argv) || argv[i] != "worktree" {
		return "", ""
	}
	op = argv[i+1]
	if op != "add" && op != "remove" {
		return "", ""
	}
	withArg := map[string]bool{"-b": true, "-B": true, "--reason": true}
	for j := i + 2; j < len(argv); j++ {
		a := argv[j]
		if withArg[a] {
			j++
			continue
		}
		if a == "--" {
			if j+1 >= len(argv) {
				return "", ""
			}
			a = argv[j+1]
		} else if strings.HasPrefix(a, "-") {
			continue
		}
		if !filepath.IsAbs(a) {
			if dir == "" {
				return "", ""
			}
			a = filepath.Join(dir, a)
		}
		return op, filepath.Clean(a)
	}
	return "", ""
}
