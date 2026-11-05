// Package storage keeps track of what Claude Code sessions leave on disk:
// each session's scratchpad (and background-task output) under
// /tmp/claude-<uid>, the git worktrees sessions create, their transcripts,
// and any extra directory the user names — with who it belongs to, what it
// holds, what removing it would free, and how full the filesystem under it is.
//
// It runs inside the daemon on one background-priority thread and writes
// three kinds of record to the store (the ai-agent hub pulls them with the
// calls):
//
//   - storage (key: the path) — one item, a new version only when it changed;
//   - disk    (key: the mount point) — a filesystem's size, free space and
//     how much of it the tracked items hold;
//   - grow    (key: the tool_use_id) — what a call added to (or removed from)
//     its session's scratchpad and worktrees.
package storage

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GabrielVidal1/claude-probe/internal/shellsplit"
	"github.com/GabrielVidal1/claude-probe/internal/store"
)

// Item is one place on disk that belongs to Claude Code sessions.
type Item struct {
	V         int      `json:"v"`
	Kind      string   `json:"kind"` // scratchpad | worktree | transcript | root
	Path      string   `json:"path"`
	Label     string   `json:"label,omitempty"`     // a root's name
	SessionID string   `json:"sessionId,omitempty"` // whose it is / who made it
	Sessions  []string `json:"sessions,omitempty"`  // every session seen working in it
	Project   string   `json:"project,omitempty"`   // the session's cwd, as Claude Code encodes it
	ConfigDir string   `json:"configDir,omitempty"` // transcripts: whose Claude config
	Bytes     int64    `json:"bytes"`               // allocated, like du
	Own       int64    `json:"own"`                 // what removing it would free
	Files     int64    `json:"files"`
	NewestAt  float64  `json:"newestAt,omitempty"`
	Partial   bool     `json:"partial,omitempty"`
	Mount     string   `json:"mount,omitempty"`
	RAM       bool     `json:"ram,omitempty"` // on a tmpfs: its bytes are memory
	Top       []Entry  `json:"top,omitempty"`
	Git       *Git     `json:"git,omitempty"`
	CreatedBy *Origin  `json:"createdBy,omitempty"`
	Gone      bool     `json:"gone,omitempty"`
	GoneAt    float64  `json:"goneAt,omitempty"`
	ScannedAt float64  `json:"scannedAt"`
	ScanMs    int64    `json:"scanMs"`
}

// Origin is the call that created a worktree.
type Origin struct {
	SessionID string  `json:"sessionId"`
	ToolUseID string  `json:"toolUseId,omitempty"`
	AgentID   string  `json:"agentId,omitempty"`
	At        float64 `json:"at"`
}

// KindTotal is what one kind of item holds on a filesystem.
type KindTotal struct {
	Items int   `json:"items"`
	Bytes int64 `json:"bytes"`
	Own   int64 `json:"own"`
}

// Disk is one filesystem under tracked items.
type Disk struct {
	V int `json:"v"`
	FS
	At           float64              `json:"at"`
	Claude       map[string]KindTotal `json:"claude"`
	EmptyScratch int                  `json:"emptyScratch,omitempty"` // session dirs with nothing in them
}

// Grow is what one call changed in its session's items.
type Grow struct {
	V         int        `json:"v"`
	ToolUseID string     `json:"toolUseId"`
	SessionID string     `json:"sessionId"`
	AgentID   string     `json:"agentId,omitempty"`
	At        float64    `json:"at"`
	Items     []GrowItem `json:"items"`
}

type GrowItem struct {
	Kind  string `json:"kind"`
	Path  string `json:"path"`
	Delta int64  `json:"delta"` // own bytes, + grew / − shrank
	Own   int64  `json:"own"`
	New   bool   `json:"new,omitempty"`
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

const (
	tickEvery     = time.Minute
	idleRescan    = 6 * 3600.0 // an item nobody touched: walked again after this
	rootRescan    = 3600.0     // an extra root
	gitRefresh    = 1800.0     // a worktree's git state (main may have moved)
	heartbeat     = 6 * 3600.0 // re-emit an unchanged item after this
	diskEvery     = 600.0      // re-emit an unchanged filesystem after this
	growMin       = 1 << 20    // a call's change worth a record
	heavyWrite    = 32 << 20   // a call that wrote this much: walk its worktrees too
	cheapFiles    = 50_000     // a scratchpad this small is walked after every call
	cheapWorktree = 400_000    // a worktree this small is walked after a heavy call
	sessionMemory = 30 * 86400.0
)

// Scanner is the daemon's storage tracker.
type Scanner struct {
	st  *store.Store
	uid int

	mu       sync.Mutex
	items    map[string]*Item   // path → the last version written
	walked   map[string]float64 // path → when last walked
	gitAt    map[string]float64
	cwds     map[string]map[string]float64 // cwd → session → last seen
	touched  map[string]float64            // session → last activity
	origins  map[string]Origin             // worktree path → its creator
	repos    map[string]bool               // git common dirs worth listing
	cfgDirs  map[string]bool
	tmpRoots map[string]bool
	disks    map[string]*Disk
	// ScratchRoots replaces /tmp/claude-<uid>, ConfigDirs ~/.claude (tests).
	ScratchRoots []string
	ConfigDirs   []string
	reqs         chan req
	stop         chan struct{}
	done         chan struct{}
}

type req struct {
	full    bool
	session string
	call    *callDone
	rm      *rmReq
	reply   chan struct{}
}

type rmReq struct {
	path       string
	force, dry bool
	out        Removal
	err        error
}

type callDone struct {
	sid, tid, agent, cwd, command string
	wrote                         int64
	added, removed                []string
}

// New makes a scanner over st; Start runs it.
func New(st *store.Store) *Scanner {
	s := &Scanner{st: st, uid: os.Getuid(), items: map[string]*Item{}, walked: map[string]float64{},
		gitAt: map[string]float64{}, cwds: map[string]map[string]float64{}, touched: map[string]float64{},
		origins: map[string]Origin{}, repos: map[string]bool{}, cfgDirs: map[string]bool{},
		tmpRoots: map[string]bool{}, disks: map[string]*Disk{}, reqs: make(chan req, 256),
		stop: make(chan struct{}), done: make(chan struct{})}
	return s
}

func (s *Scanner) stopping() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

func nowF() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// Start loads what the store already knows and runs the scanner's thread.
// The first pass waits `delay` so a daemon started by a hook answers first.
func (s *Scanner) Start(delay time.Duration) {
	s.load()
	go s.run(delay)
}

// Stop ends the thread and waits for it.
func (s *Scanner) Stop() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	<-s.done
}

// Scan asks for a full pass and waits for it (`claude-probe storage --scan`).
func (s *Scanner) Scan(timeout time.Duration) bool {
	r := req{full: true, reply: make(chan struct{})}
	select {
	case s.reqs <- r:
	default:
		return false
	}
	select {
	case <-r.reply:
		return true
	case <-time.After(timeout):
		return false
	}
}

// RemoveNow runs Remove on the scanner's thread (the daemon's API).
func (s *Scanner) RemoveNow(path string, force, dry bool, timeout time.Duration) (Removal, error) {
	rr := &rmReq{path: path, force: force, dry: dry}
	r := req{rm: rr, reply: make(chan struct{})}
	select {
	case s.reqs <- r:
	case <-time.After(timeout):
		return Removal{Path: path}, fmt.Errorf("the scanner is busy")
	}
	select {
	case <-r.reply:
		return rr.out, rr.err
	case <-time.After(timeout):
		return Removal{Path: path}, fmt.Errorf("timed out")
	}
}

// Load reads back what the store knows, for a scanner used outside the
// daemon (the CLI, when no daemon runs).
func (s *Scanner) Load() { s.load() }

// Pass runs one pass on the calling goroutine.
func (s *Scanner) Pass(full bool) { s.pass(full) }

// Touch records a hook event: the session is active, from that cwd.
func (s *Scanner) Touch(sid, cwd, configDir, tmpDir string, end bool) {
	if sid == "" {
		return
	}
	now := nowF()
	s.mu.Lock()
	s.touched[sid] = now
	if cwd != "" {
		if s.cwds[cwd] == nil {
			s.cwds[cwd] = map[string]float64{}
			if c := commonDir(cwd); c != "" {
				s.repos[c] = true
			}
		}
		s.cwds[cwd][sid] = now
	}
	if configDir != "" {
		s.cfgDirs[configDir] = true
	}
	if tmpDir != "" {
		s.tmpRoots[filepath.Join(tmpDir, fmt.Sprintf("claude-%d", s.uid))] = true
	}
	s.mu.Unlock()
	if end {
		s.ask(req{session: sid})
	}
}

// CallDone takes a finished call record (the probe's `call`): its session's
// scratchpad is measured again, its worktrees too when it wrote a lot, and
// whatever changed is pinned on it.
func (s *Scanner) CallDone(rec map[string]any) {
	sid, _ := rec["sessionId"].(string)
	tid, _ := rec["toolUseId"].(string)
	if sid == "" || tid == "" {
		return
	}
	c := &callDone{sid: sid, tid: tid}
	c.agent, _ = rec["agentId"].(string)
	c.cwd, _ = rec["cwd"].(string)
	c.command, _ = rec["command"].(string)
	if t, ok := rec["totals"].(map[string]any); ok {
		if io, ok := t["io"].(map[string]int64); ok {
			c.wrote = max(io["wchar"], io["write_bytes"])
		}
	}
	if procs, ok := rec["procs"].([]map[string]any); ok {
		for _, p := range procs {
			argv, _ := p["argv"].(string)
			if !strings.Contains(argv, "worktree") {
				continue
			}
			switch op, path := WorktreeOp(strings.Fields(argv), c.cwd); op {
			case "add":
				c.added = append(c.added, path)
			case "remove":
				c.removed = append(c.removed, path)
			}
		}
	}
	s.ask(req{call: c})
}

func (s *Scanner) ask(r req) {
	select {
	case s.reqs <- r:
	default: // full: the next pass catches up
	}
}

// load reads back what the store knows: the items written before (so an
// unchanged one isn't written again), the creators, every session's cwds.
func (s *Scanner) load() {
	now := nowF()
	if recs, err := s.st.Latest("storage", "", 0); err == nil {
		for _, r := range recs {
			var it Item
			if json.Unmarshal(r.Data, &it) == nil && !it.Gone {
				s.items[it.Path] = &it
				s.walked[it.Path] = it.ScannedAt
				if it.Git != nil {
					s.gitAt[it.Path] = it.Git.At
				}
				if it.CreatedBy != nil {
					s.origins[it.Path] = *it.CreatedBy
				}
				if it.Kind == "worktree" && it.V >= 2 { // v1 counted any mention of the path
					for _, sid := range it.Sessions { // who worked in it, cwd or not
						if s.cwds[it.Path] == nil {
							s.cwds[it.Path] = map[string]float64{}
						}
						if s.cwds[it.Path][sid] == 0 {
							s.cwds[it.Path][sid] = it.ScannedAt
						}
					}
				}
			}
		}
	}
	if recs, err := s.st.Latest("wtorigin", "", 0); err == nil {
		for _, r := range recs {
			var o struct {
				Path string `json:"path"`
				Origin
			}
			if json.Unmarshal(r.Data, &o) == nil && o.Path != "" {
				s.origins[o.Path] = o.Origin
			}
		}
	}
	if rows, err := s.st.Cwds(now - sessionMemory); err == nil {
		for _, c := range rows {
			if s.cwds[c.Cwd] == nil {
				s.cwds[c.Cwd] = map[string]float64{}
			}
			s.cwds[c.Cwd][c.Session] = c.At
			if c.At > s.touched[c.Session] {
				s.touched[c.Session] = c.At
			}
		}
	}
	for cwd := range s.cwds {
		if c := commonDir(cwd); c != "" {
			s.repos[c] = true
		}
	}
	for p := range s.origins {
		if c := commonDir(filepath.Dir(p)); c != "" {
			s.repos[c] = true
		}
	}
	for _, d := range s.st.Strings("mark", "configDir") {
		s.cfgDirs[d] = true
	}
}

func (s *Scanner) run(delay time.Duration) {
	defer close(s.done)
	background()
	first := time.NewTimer(delay)
	tick := time.NewTicker(tickEvery)
	defer tick.Stop()
	started := false
	for {
		select {
		case <-s.stop:
			return
		case <-first.C:
			started = true
			s.pass(false)
		case <-tick.C:
			if started {
				s.pass(false)
			}
		case r := <-s.reqs:
			switch {
			case r.full:
				started = true
				s.pass(true)
			case r.call != nil:
				s.afterCall(r.call)
			case r.session != "":
				s.refreshSession(r.session)
			case r.rm != nil:
				r.rm.out, r.rm.err = s.Remove(r.rm.path, r.rm.force, r.rm.dry)
				s.writeDisks(nowF(), nil, false)
			}
			if r.reply != nil {
				close(r.reply)
			}
		}
	}
}

// candidate is something that should be measured.
type candidate struct {
	kind, path, sid, project, cfg, label, expand string
	admin, common                                string // worktrees
	jsonl                                        string // transcripts: the .jsonl beside the dir
}

func (s *Scanner) scratchRoots(cfg Config) []string {
	roots := map[string]bool{}
	for _, r := range s.ScratchRoots {
		roots[r] = true
	}
	if len(roots) == 0 {
		roots[fmt.Sprintf("/tmp/claude-%d", s.uid)] = true
	}
	if d := os.Getenv("CLAUDE_CODE_TMPDIR"); d != "" && len(s.ScratchRoots) == 0 {
		roots[filepath.Join(d, fmt.Sprintf("claude-%d", s.uid))] = true
	}
	s.mu.Lock()
	for r := range s.tmpRoots {
		roots[r] = true
	}
	s.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for r := range roots {
		if real, err := filepath.EvalSymlinks(r); err == nil && !seen[real] {
			seen[real] = true
			out = append(out, real)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Scanner) configDirs() []string {
	if s.ConfigDirs != nil {
		return s.ConfigDirs
	}
	home, _ := os.UserHomeDir()
	dirs := map[string]bool{filepath.Join(home, ".claude"): true}
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		dirs[d] = true
	}
	s.mu.Lock()
	for d := range s.cfgDirs {
		dirs[d] = true
	}
	s.mu.Unlock()
	var out []string
	for d := range dirs {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// empty says whether a session's scratch dir holds no file at all (Claude
// Code makes one, with an empty scratchpad/, for every session).
func empty(dir string) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return true
	}
	for _, e := range ents {
		if !e.IsDir() {
			return false
		}
		sub, err := os.ReadDir(filepath.Join(dir, e.Name()))
		if err != nil || len(sub) > 0 {
			return false
		}
	}
	return true
}

// discover lists everything to measure, and how many session dirs are empty
// per scratch root.
func (s *Scanner) discover(cfg Config) ([]candidate, map[string]int) {
	var out []candidate
	emptyBy := map[string]int{}
	for _, root := range s.scratchRoots(cfg) {
		projects, _ := os.ReadDir(root)
		for _, p := range projects {
			if !p.IsDir() {
				continue
			}
			pdir := filepath.Join(root, p.Name())
			sessions, _ := os.ReadDir(pdir)
			for _, se := range sessions {
				if !se.IsDir() || !uuidRE.MatchString(se.Name()) {
					continue
				}
				dir := filepath.Join(pdir, se.Name())
				if empty(dir) {
					emptyBy[root]++
					continue
				}
				out = append(out, candidate{kind: "scratchpad", path: dir, sid: se.Name(),
					project: p.Name(), expand: "scratchpad"})
			}
		}
	}
	seen := map[string]bool{}
	for _, cfgDir := range s.configDirs() {
		pr := filepath.Join(cfgDir, "projects")
		real, err := filepath.EvalSymlinks(pr)
		if err != nil || seen[real] {
			continue
		}
		seen[real] = true
		projects, _ := os.ReadDir(real)
		for _, p := range projects {
			if !p.IsDir() {
				continue
			}
			pdir := filepath.Join(real, p.Name())
			files, _ := os.ReadDir(pdir)
			for _, f := range files {
				name := f.Name()
				if f.IsDir() || !strings.HasSuffix(name, ".jsonl") || !uuidRE.MatchString(strings.TrimSuffix(name, ".jsonl")) {
					continue
				}
				sid := strings.TrimSuffix(name, ".jsonl")
				out = append(out, candidate{kind: "transcript", path: filepath.Join(pdir, sid), sid: sid,
					project: p.Name(), cfg: cfgDir, jsonl: filepath.Join(pdir, name)})
			}
		}
	}
	for _, r := range cfg.Roots {
		p := expandHome(r.Path)
		if r.Worktrees {
			ents, _ := os.ReadDir(p)
			for _, e := range ents {
				if e.IsDir() {
					if c := commonDir(filepath.Join(p, e.Name())); c != "" {
						s.mu.Lock()
						s.repos[c] = true
						s.mu.Unlock()
					}
				}
			}
			continue
		}
		if _, err := os.Stat(p); err == nil {
			out = append(out, candidate{kind: "root", path: p, label: r.Label})
		}
	}
	s.mu.Lock()
	repos := make([]string, 0, len(s.repos))
	for c := range s.repos {
		repos = append(repos, c)
	}
	s.mu.Unlock()
	sort.Strings(repos)
	wseen := map[string]bool{}
	for _, common := range repos {
		if _, err := os.Stat(common); err != nil {
			s.mu.Lock()
			delete(s.repos, common)
			s.mu.Unlock()
			continue
		}
		for wt, admin := range worktreesOf(common) {
			if wseen[wt] {
				continue
			}
			wseen[wt] = true
			if _, err := os.Stat(wt); err != nil {
				continue // its directory is gone (git hasn't pruned it): nothing on disk
			}
			out = append(out, candidate{kind: "worktree", path: wt, admin: admin, common: common})
		}
	}
	return out, emptyBy
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}

// sessionsIn lists the sessions seen working inside dir, oldest first.
func (s *Scanner) sessionsIn(dir string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	first := map[string]float64{}
	pre := strings.TrimSuffix(dir, "/") + "/"
	for cwd, by := range s.cwds {
		if cwd != dir && !strings.HasPrefix(cwd, pre) {
			continue
		}
		for sid, at := range by {
			if f, ok := first[sid]; !ok || at < f {
				first[sid] = at
			}
		}
	}
	out := make([]string, 0, len(first))
	for sid := range first {
		out = append(out, sid)
	}
	sort.Slice(out, func(i, j int) bool { return first[out[i]] < first[out[j]] })
	return out
}

func (s *Scanner) lastTouch(sids ...string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := 0.0
	for _, sid := range sids {
		t = math.Max(t, s.touched[sid])
	}
	return t
}

// due says whether c should be walked now.
func (s *Scanner) due(c candidate, now float64) bool {
	last, ok := s.walked[c.path]
	if !ok {
		return true
	}
	switch c.kind {
	case "scratchpad":
		return s.lastTouch(c.sid) > last || now-last > idleRescan
	case "transcript":
		return mtime(c.jsonl) > last || now-last > idleRescan
	case "worktree":
		sids := s.sessionsIn(c.path)
		if o, ok := s.origins[c.path]; ok {
			sids = append(sids, o.SessionID)
		}
		return activity(c.admin) > last || s.lastTouch(sids...) > last || now-last > idleRescan
	default:
		return now-last > rootRescan
	}
}

// measure walks one candidate into an item.
func (s *Scanner) measure(c candidate, now float64, withGit bool) *Item {
	t0 := time.Now()
	it := &Item{V: 2, Kind: c.kind, Path: c.path, SessionID: c.sid, Project: c.project,
		ConfigDir: c.cfg, Label: c.label}
	var t Tally
	switch c.kind {
	case "transcript":
		t = WalkAbort(c.path, true, "", s.stopping) // subagents/, tool-results/ (may not exist)
		jt := Walk(c.jsonl, false, "")
		t.Bytes += jt.Bytes
		t.Own += jt.Own
		t.Files += jt.Files
		t.Newest = math.Max(t.Newest, jt.Newest)
		t.Children = append(t.Children, Entry{Name: "transcript", Bytes: jt.Bytes, Own: jt.Own, Files: jt.Files})
		sort.Slice(t.Children, func(i, j int) bool { return t.Children[i].Own > t.Children[j].Own })
	default:
		t = WalkAbort(c.path, true, c.expand, s.stopping)
	}
	if t.Partial && s.stopping() {
		return nil // interrupted: not a measurement
	}
	it.Bytes, it.Own, it.Files, it.NewestAt, it.Partial = t.Bytes, t.Own, t.Files, r3(t.Newest), t.Partial
	for _, e := range t.Children {
		if len(it.Top) >= 8 || (e.Own < 1<<20 && e.Bytes < 1<<20 && len(it.Top) >= 3) {
			break
		}
		it.Top = append(it.Top, e)
	}
	if fs, ok := FSOf(c.path); ok {
		it.Mount, it.RAM = fs.Mount, fs.RAM
	}
	if c.kind == "worktree" {
		it.Sessions = s.sessionsIn(c.path)
		if o, ok := s.origins[c.path]; ok {
			oc := o
			it.CreatedBy = &oc
			it.SessionID = o.SessionID
		} else if len(it.Sessions) > 0 {
			it.SessionID = it.Sessions[0]
		}
		prev := s.items[c.path]
		if withGit || prev == nil || prev.Git == nil || now-s.gitAt[c.path] > gitRefresh {
			it.Git = readGit(c.path, c.admin, c.common, now)
			s.gitAt[c.path] = now
		} else {
			it.Git = prev.Git
		}
	}
	it.ScannedAt = r3(now)
	it.ScanMs = time.Since(t0).Milliseconds()
	return it
}

func r3(x float64) float64 { return math.Round(x*1000) / 1000 }

// changed says whether the new version is worth writing.
func changed(prev, it *Item, now float64) bool {
	if prev == nil {
		return true
	}
	if now-prev.ScannedAt > heartbeat {
		return true
	}
	big := func(a, b int64) bool {
		d := a - b
		if d < 0 {
			d = -d
		}
		return d >= 64<<10 && float64(d) >= 0.002*float64(max(a, b))
	}
	if big(prev.Bytes, it.Bytes) || big(prev.Own, it.Own) || prev.Partial != it.Partial ||
		prev.SessionID != it.SessionID || strings.Join(prev.Sessions, ",") != strings.Join(it.Sessions, ",") {
		return true
	}
	if (prev.CreatedBy == nil) != (it.CreatedBy == nil) {
		return true
	}
	if prev.Git != nil && it.Git != nil {
		a, b := *prev.Git, *it.Git
		a.At, b.At, a.IdleFor, b.IdleFor = 0, 0, 0, 0
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		return string(ja) != string(jb)
	}
	return false
}

func (s *Scanner) put(it *Item) {
	_ = s.st.Put("storage", it.SessionID, it.Path, it)
	s.items[it.Path] = it
}

func (s *Scanner) gone(path string, now float64) {
	prev := s.items[path]
	if prev == nil {
		return
	}
	g := *prev
	g.Gone, g.GoneAt, g.Bytes, g.Own, g.Files, g.Top, g.ScannedAt = true, r3(now), 0, 0, 0, nil, r3(now)
	_ = s.st.Put("storage", g.SessionID, g.Path, &g)
	delete(s.items, path)
	delete(s.walked, path)
	delete(s.gitAt, path)
}

// pass measures what is due (everything when full) and writes what changed.
func (s *Scanner) pass(full bool) {
	t0 := time.Now()
	now := nowF()
	cfg := LoadConfig()
	cands, emptyBy := s.discover(cfg)
	present := map[string]bool{}
	walked := 0
	for _, c := range cands {
		select {
		case <-s.stop:
			return
		default:
		}
		present[c.path] = true
		if !full && !s.due(c, now) {
			continue
		}
		it := s.measure(c, now, full)
		if it == nil {
			return
		}
		s.walked[c.path] = now
		walked++
		if changed(s.items[c.path], it, now) {
			s.put(it)
		}
	}
	for p := range s.items {
		if !present[p] {
			s.gone(p, now)
		}
	}
	s.writeDisks(now, emptyBy, full)
	if full || walked > 50 {
		log.Printf("storage: %d items, %d walked in %s", len(cands), walked, time.Since(t0).Round(time.Millisecond))
	}
	if cfg.Clean.On() {
		s.autoClean(cfg, now)
	}
}

func (s *Scanner) writeDisks(now float64, emptyBy map[string]int, force bool) {
	byMount := map[string]*Disk{}
	paths := map[string]string{}
	for _, it := range s.items {
		if it.Mount == "" {
			continue
		}
		d := byMount[it.Mount]
		if d == nil {
			d = &Disk{V: 1, Claude: map[string]KindTotal{}}
			byMount[it.Mount] = d
			paths[it.Mount] = it.Path
		}
		k := d.Claude[it.Kind]
		k.Items++
		k.Bytes += it.Bytes
		k.Own += it.Own
		d.Claude[it.Kind] = k
	}
	for root, n := range emptyBy {
		fs, ok := FSOf(root)
		if !ok {
			continue
		}
		d := byMount[fs.Mount]
		if d == nil {
			d = &Disk{V: 1, Claude: map[string]KindTotal{}}
			byMount[fs.Mount] = d
			paths[fs.Mount] = root
		}
		d.EmptyScratch += n
	}
	for mount, d := range byMount {
		fs, ok := FSOf(paths[mount])
		if !ok {
			continue
		}
		d.FS, d.At = fs, r3(now)
		prev := s.disks[mount]
		if !force && prev != nil && now-prev.At < diskEvery &&
			math.Abs(float64(prev.Avail-d.Avail)) < 0.005*float64(d.Total) && sameTotals(prev, d) {
			continue
		}
		_ = s.st.Put("disk", "", mount, d)
		s.disks[mount] = d
	}
}

func sameTotals(a, b *Disk) bool {
	if a.EmptyScratch != b.EmptyScratch || len(a.Claude) != len(b.Claude) {
		return false
	}
	for k, v := range a.Claude {
		w := b.Claude[k]
		if v.Items != w.Items || math.Abs(float64(v.Own-w.Own)) > 0.002*float64(max(v.Own, w.Own))+(1<<20) {
			return false
		}
	}
	return true
}

// itemsOf lists the items a session owns or worked in.
func (s *Scanner) itemsOf(sid string) []*Item {
	var out []*Item
	for _, it := range s.items {
		if it.SessionID == sid {
			out = append(out, it)
			continue
		}
		for _, x := range it.Sessions {
			if x == sid {
				out = append(out, it)
				break
			}
		}
	}
	return out
}

// scratchOf finds a session's scratch dir candidate (it may be new).
func (s *Scanner) scratchOf(sid string) *candidate {
	for _, root := range s.scratchRoots(Config{}) {
		matches, _ := filepath.Glob(filepath.Join(root, "*", sid))
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.IsDir() && !empty(m) {
				return &candidate{kind: "scratchpad", path: m, sid: sid,
					project: filepath.Base(filepath.Dir(m)), expand: "scratchpad"}
			}
		}
	}
	return nil
}

func (s *Scanner) worktreeCand(path string) *candidate {
	admin := gitdirOf(path)
	if admin == "" {
		return nil
	}
	return &candidate{kind: "worktree", path: path, admin: admin, common: commonOf(admin)}
}

// remeasure walks the given candidates now and returns what changed.
func (s *Scanner) remeasure(cands []candidate, now float64) []GrowItem {
	var out []GrowItem
	for _, c := range cands {
		prev := s.items[c.path]
		it := s.measure(c, now, c.kind == "worktree")
		if it == nil {
			return out
		}
		s.walked[c.path] = now
		var before int64
		if prev != nil {
			before = prev.Own
		}
		if d := it.Own - before; d >= growMin || d <= -growMin {
			out = append(out, GrowItem{Kind: c.kind, Path: c.path, Delta: d, Own: it.Own, New: prev == nil})
		}
		if changed(prev, it, now) {
			s.put(it)
		}
	}
	return out
}

// workDirs are the directories a command works in: the targets of its
// `cd` / `pushd` parts and of `-C <dir>` (git, make…) — read with the shell
// splitter, so a path that is only text (an echo, a heredoc body, a grep
// pattern) doesn't count.
func workDirs(command, cwd string) []string {
	home, _ := os.UserHomeDir()
	abs := func(w string) string {
		w = strings.Trim(w, `'"`)
		switch {
		case w == "~":
			return home
		case strings.HasPrefix(w, "~/"):
			return filepath.Join(home, w[2:])
		case strings.HasPrefix(w, "$HOME/"):
			return filepath.Join(home, w[6:])
		case filepath.IsAbs(w):
			return filepath.Clean(w)
		case cwd != "":
			return filepath.Join(cwd, w)
		}
		return ""
	}
	var out []string
	for _, part := range shellsplit.Split(command) {
		words := strings.Fields(part.Text)
		for i, w := range words {
			if i+1 >= len(words) {
				break
			}
			if (i == 0 && (w == "cd" || w == "pushd")) || w == "-C" {
				if d := abs(words[i+1]); d != "" {
					out = append(out, d)
				}
			}
		}
	}
	return out
}

// mentioned records the worktrees a call worked in by `cd` or `-C`: Claude
// Code puts every call back in the session's own directory, so a session
// working in a worktree rarely has it as its cwd.
func (s *Scanner) mentioned(c *callDone, now float64) {
	dirs := workDirs(c.command, c.cwd)
	if len(dirs) == 0 {
		return
	}
	for p, it := range s.items {
		if it.Kind != "worktree" {
			continue
		}
		pre := strings.TrimSuffix(p, "/") + "/"
		hit := false
		for _, d := range dirs {
			if d == p || strings.HasPrefix(d, pre) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		s.mu.Lock()
		if s.cwds[p] == nil {
			s.cwds[p] = map[string]float64{}
		}
		s.cwds[p][c.sid] = now
		s.mu.Unlock()
	}
}

// afterCall measures what one call may have changed and pins it on the call.
func (s *Scanner) afterCall(c *callDone) {
	now := nowF()
	s.mentioned(c, now)
	var cands []candidate
	if sc := s.scratchOf(c.sid); sc != nil {
		if prev := s.items[sc.path]; prev == nil || prev.Files < cheapFiles || c.wrote >= heavyWrite {
			cands = append(cands, *sc)
		}
	}
	for _, p := range c.added {
		o := Origin{SessionID: c.sid, ToolUseID: c.tid, AgentID: c.agent, At: r3(now)}
		s.origins[p] = o
		_ = s.st.Put("wtorigin", c.sid, p, map[string]any{"v": 1, "path": p, "sessionId": o.SessionID,
			"toolUseId": o.ToolUseID, "agentId": o.AgentID, "at": o.At})
		if cc := s.worktreeCand(p); cc != nil {
			s.mu.Lock()
			s.repos[cc.common] = true
			s.mu.Unlock()
			cands = append(cands, *cc)
		}
	}
	var gone []GrowItem
	for _, p := range c.removed {
		if prev := s.items[p]; prev != nil {
			if _, err := os.Stat(p); err != nil {
				gone = append(gone, GrowItem{Kind: prev.Kind, Path: p, Delta: -prev.Own})
				s.gone(p, now)
			}
		}
	}
	if c.wrote >= heavyWrite {
		seen := map[string]bool{}
		for _, cc := range cands {
			seen[cc.path] = true
		}
		for _, it := range s.itemsOf(c.sid) {
			if it.Kind == "worktree" && !seen[it.Path] && it.Files < cheapWorktree {
				if cc := s.worktreeCand(it.Path); cc != nil {
					cands = append(cands, *cc)
				}
			}
		}
	}
	grow := append(s.remeasure(cands, now), gone...)
	if len(grow) > 0 {
		_ = s.st.Put("grow", c.sid, c.tid, &Grow{V: 1, ToolUseID: c.tid, SessionID: c.sid,
			AgentID: c.agent, At: r3(now), Items: grow})
	}
}

// refreshSession measures a session's items at the end of one of its turns.
func (s *Scanner) refreshSession(sid string) {
	now := nowF()
	var cands []candidate
	if sc := s.scratchOf(sid); sc != nil {
		cands = append(cands, *sc)
	}
	for _, it := range s.itemsOf(sid) {
		if it.Kind == "worktree" && it.Files < cheapWorktree {
			if cc := s.worktreeCand(it.Path); cc != nil {
				cands = append(cands, *cc)
			}
		}
	}
	s.remeasure(cands, now)
}
