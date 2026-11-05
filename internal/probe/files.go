package probe

import (
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Claude Code's own per-call file (the shell's cwd, written by the call's
// shell and removed by claude itself — whose writes aren't followed).
var ccCwdFile = regexp.MustCompile(`^(/private)?/tmp/claude-[0-9a-f]+-cwd$`)

// settleS: a process's files are released just after its exit is reported
// (exit_files runs after the exit tracepoint) — the call waits this long
// after its last exit before its final record.
const settleS = 0.3

// fileAgg adds up what one call did to the disk, from its processes' file
// events: allocated bytes written and freed, the files it created and
// deleted, the biggest ones (merged per inode: a log appended a thousand
// times is one line) and the directories that took the most.
func fileAgg(evs []FileEv) map[string]any {
	if len(evs) == 0 {
		return nil
	}
	type agg struct {
		path          string
		delta, dsize  int64
		size          int64
		created, gone bool
		op            string
		last          float64
	}
	byIno := map[[2]uint64]*agg{}
	var written, freed, logical int64
	created, deleted := 0, 0
	// an unlink names at most 4 levels ("…/a/b/name"): a directory a write
	// named in full completes it
	absDirs := map[string]bool{}
	for _, e := range evs {
		if e.Op == "write" && strings.HasPrefix(e.Path, "/") {
			absDirs[filepath.Dir(e.Path)] = true
		}
	}
	for i, e := range evs {
		if strings.HasPrefix(e.Path, "…/") {
			suffix := "/" + filepath.Dir(strings.TrimPrefix(e.Path, "…/"))
			for d := range absDirs {
				if strings.HasSuffix(d, suffix) {
					evs[i].Path = d + "/" + filepath.Base(e.Path)
					break
				}
			}
		}
	}
	n := 0
	for _, e := range evs {
		if ccCwdFile.MatchString(e.Path) {
			continue
		}
		n++
		if e.Delta > 0 {
			written += e.Delta
		} else {
			freed += -e.Delta
		}
		logical += e.DSize
		if e.Created {
			created++
		}
		if e.Op != "write" {
			deleted++
		}
		k := [2]uint64{e.Dev, e.Ino}
		a := byIno[k]
		if a == nil {
			a = &agg{}
			byIno[k] = a
		}
		a.delta += e.Delta
		a.dsize += e.DSize
		a.created = a.created || e.Created
		if e.T >= a.last {
			a.last, a.op, a.size = e.T, e.Op, e.Size
			a.gone = e.Op != "write"
			if e.Path != "" && (a.path == "" || e.Op == "write" || strings.HasPrefix(a.path, "…")) {
				a.path = e.Path
			}
		}
	}
	all := make([]*agg, 0, len(byIno))
	for _, a := range byIno {
		all = append(all, a)
	}
	sort.Slice(all, func(i, j int) bool { return abs64(all[i].delta) > abs64(all[j].delta) })
	var top []map[string]any
	for _, a := range all {
		if len(top) == 12 {
			break
		}
		if a.delta == 0 && (!a.created || a.gone) {
			continue // unchanged, or a temp file the call made and removed
		}
		m := map[string]any{"path": a.path, "delta": a.delta, "size": a.size, "op": a.op}
		if a.created {
			m["created"] = true
		}
		if a.gone {
			m["deleted"] = true
		}
		top = append(top, m)
	}
	dirs := map[string]*[2]int64{} // dir → {net, files}
	for _, a := range all {
		d := dirKey(a.path)
		if dirs[d] == nil {
			dirs[d] = &[2]int64{}
		}
		dirs[d][0] += a.delta
		dirs[d][1]++
	}
	type dv struct {
		dir        string
		net, files int64
	}
	var dl []dv
	for d, v := range dirs {
		dl = append(dl, dv{d, v[0], v[1]})
	}
	sort.Slice(dl, func(i, j int) bool { return abs64(dl[i].net) > abs64(dl[j].net) })
	var dout []map[string]any
	for _, d := range dl {
		if len(dout) == 6 || d.net == 0 {
			break
		}
		dout = append(dout, map[string]any{"dir": d.dir, "net": d.net, "files": d.files})
	}
	out := map[string]any{"v": 1, "written": written, "freed": freed, "net": written - freed,
		"logical": logical, "created": created, "deleted": deleted, "files": len(byIno),
		"events": n, "exact": true}
	if top != nil {
		out["top"] = top
	}
	if dout != nil {
		out["dirs"] = dout
	}
	return out
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// dirKey groups a file under a directory a person would name: its parent,
// cut at node_modules / target / dist / .git and the like (one line for a
// 40 000-file install), and at most 6 levels deep.
func dirKey(p string) string {
	if p == "" {
		return "?"
	}
	d := filepath.Dir(p)
	parts := strings.Split(d, "/")
	for i, x := range parts {
		switch x {
		case "node_modules", "target", "dist", "build", ".git", ".venv", "__pycache__", ".next", ".cache":
			return strings.Join(parts[:i+1], "/")
		}
	}
	if len(parts) > 7 {
		parts = parts[:7]
	}
	return strings.Join(parts, "/")
}

// lastExit is when the call's last process exited (0 if one still runs).
func (c *Call) lastExit() float64 {
	t := 0.0
	for _, p := range c.procs {
		if !p.Dead {
			return 0
		}
		t = math.Max(t, p.End)
	}
	return t
}

// files is the call's file record (nil when the kernel layer doesn't
// report files, or the call touched none).
func (pr *Probe) files(c *Call) map[string]any {
	if pr.Feed == nil || !pr.Feed.FilesOn || !c.exact {
		return nil
	}
	var evs []FileEv
	seen := map[int]bool{}
	for _, p := range c.procs {
		if seen[p.Pid] {
			continue // an exec in place: the same pid, one incarnation
		}
		seen[p.Pid] = true
		evs = append(evs, pr.Feed.FilesOf(p.Pid, p.Started)...)
	}
	for _, x := range c.extra {
		if !seen[x.Pid] {
			seen[x.Pid] = true
			evs = append(evs, pr.Feed.FilesOf(x.Pid, x.Started)...)
		}
	}
	return fileAgg(evs)
}
