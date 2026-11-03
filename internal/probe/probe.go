// Package probe measures what each Bash call — and every process it started
// — cost, while it runs.
//
// The hook tells it when a call starts (before Claude Code spawns the call's
// `bash -c "… eval '<cmd>' …"`), with the ids Claude Code hands every hook:
// tool_use_id, prompt_id and, inside a subagent, agent_id. The probe walks
// the hook's PID chain to the session's `claude`, takes its new eval-shell
// child whose command matches (rtk's rewrite stripped; else first in, first
// out), then follows the shell's processes:
//
//   - kernel (exact): the eBPF layer's fork tree, each exit's own CPU, peak
//     RSS, I/O and exit status — processes that lived a millisecond included;
//   - sampled: /proc/<pid>/task/*/children of the call's subtree only, fast
//     at first (most calls last under a second), then at Hz.
//
// Background work (run_in_background, `cmd &`, a setsid daemon) is followed
// until its last process exits or BgCap passes.
package probe

import (
	"encoding/json"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/GabrielVidal1/claude-probe/internal/plan"
	"github.com/GabrielVidal1/claude-probe/internal/store"
)

var (
	Hz           = 4.0
	BgCapS       = 24 * 3600.0
	fastS        = 0.6
	fastDt       = 0.02
	midS         = 5.0
	midDt        = 0.1
	findTimeoutS = 4.0
	runningEvery = 10.0
	maxProcs     = 200
	maxArgv      = 400
	drmRescanS   = 5.0
)

var ioKeys = []string{"rchar", "wchar", "read_bytes", "write_bytes"}

// Event is what the hook sends.
type Event struct {
	E           string  `json:"e"`
	T           float64 `json:"t"`
	Sid         string  `json:"sid"`
	PromptID    string  `json:"promptId,omitempty"`
	AgentID     string  `json:"agentId,omitempty"`
	AgentType   string  `json:"agentType,omitempty"`
	Cwd         string  `json:"cwd,omitempty"`
	Effort      string  `json:"effort,omitempty"`
	ConfigDir   string  `json:"configDir,omitempty"`
	Tid         string  `json:"tid,omitempty"`
	Tool        string  `json:"tool,omitempty"`
	Command     string  `json:"command,omitempty"`
	Bg          bool    `json:"bg,omitempty"`
	Chain       []int   `json:"chain,omitempty"`
	DurationMs  *int64  `json:"durationMs,omitempty"`
	BgTask      string  `json:"bgTask,omitempty"`
	Interrupted bool    `json:"interrupted,omitempty"`
	BgTasks     *int    `json:"bgTasks,omitempty"`
}

// TP is a tracked process of one call.
type TP struct {
	Pid       int
	Start     float64 // fingerprint (ticks on Linux, epoch otherwise)
	Started   float64 // epoch
	Ppid      int
	Parent    *TP
	Argv      string
	Label     string
	Depth     int
	Via       string
	Own, Cum  float64
	own0      float64
	cum0      float64
	HWM, RSS  int64
	RSSMax    int64
	IO        map[string]int64
	io0       map[string]int64
	drm       []string
	drmAt     float64
	gpu0      *int64
	GPU       int64
	GPUMem    int64
	Threads   int
	Dead      bool
	End       float64
	Unseen    float64
	Final     *float64
	Exact     bool // its exit came from the kernel layer, with exact numbers
	exited    bool // the kernel layer reported its exit (exact or not)
	raw       string
	Code      *int
	Signal    *int
	Reaper    int
}

func newTP(pid int, start, started float64, ppid int, parent *TP, argv []string, comm, via string, depth int) *TP {
	tp := &TP{Pid: pid, Start: start, Started: started, Ppid: ppid, Parent: parent, Via: via,
		Depth: depth, Threads: 1, IO: map[string]int64{}, io0: map[string]int64{}}
	tp.setArgv(argv, comm)
	return tp
}

// setArgv names the process by its command line — again after an exec in
// place (`bash -c 'cmd'` becoming cmd, a subshell's last command).
func (p *TP) setArgv(argv []string, comm string) {
	cmdline := joinArgv(argv)
	p.raw = cmdline
	if cmdline == "" {
		cmdline = comm
	}
	p.Argv = trim(Redact(cmdline), maxArgv)
	if tool := ToolCommand(argv); tool != "" {
		p.Label = CommandLabel(tool)
	} else {
		p.Label = Label(argv, comm)
	}
}

func joinArgv(a []string) string {
	s := ""
	for i, x := range a {
		if i > 0 {
			s += " "
		}
		s += x
	}
	return s
}

func tpFromProc(pid int, st *Stat, parent *TP, via string, depth int, bornIn bool) *TP {
	tp := newTP(pid, st.Start, st.Started, st.Ppid, parent, argvOf(pid), st.Comm, via, depth)
	if !bornIn { // a process that predates the call counts from now on
		tp.own0, tp.cum0 = st.Own, st.Cum
		for k, v := range st.IO {
			tp.io0[k] = v
		}
	}
	tp.update(st, nowF())
	return tp
}

func tpFromKernel(bp BP, parent *TP, depth int) *TP {
	var st *Stat
	if bp.Exit == nil {
		if s := readStat(bp.Pid); s != nil && math.Abs(s.Started-bp.Start) <= matchS {
			st = s
		}
	}
	argv := bp.Argv
	if len(argv) == 0 && st != nil {
		argv = argvOf(bp.Pid)
	}
	start := math.Round(bp.Start*100) / 100
	if st != nil {
		start = st.Start
	}
	tp := newTP(bp.Pid, start, bp.Start, bp.Ppid, parent, argv, bp.Comm, "kernel", depth)
	if st != nil {
		tp.update(st, nowF())
	}
	if bp.Exit != nil {
		tp.applyExit(bp.Exit)
	}
	return tp
}

func (p *TP) update(st *Stat, now float64) {
	p.Ppid = st.Ppid
	p.Own = math.Max(p.Own, st.Own-p.own0)
	p.Cum = math.Max(p.Cum, st.Cum-p.cum0)
	p.RSS = st.RSS
	p.RSSMax = max(p.RSSMax, st.RSS)
	p.HWM = max(p.HWM, st.HWM)
	p.Threads = max(p.Threads, st.Threads)
	for _, k := range ioKeys {
		if v, ok := st.IO[k]; ok {
			p.IO[k] = max(p.IO[k], v-p.io0[k])
		}
	}
	if now-p.drmAt >= drmRescanS {
		p.drm, p.drmAt = drmFds(p.Pid), now
	}
	if len(p.drm) > 0 {
		if ns, mem, ok := gpuOf(p.Pid, p.drm); ok {
			if p.gpu0 == nil {
				p.gpu0 = &ns
			}
			p.GPU = max(p.GPU, ns-*p.gpu0)
			p.GPUMem = max(p.GPUMem, mem)
		}
	}
}

// applyExit takes the kernel's numbers at exit — exact, they replace the samples.
func (p *TP) applyExit(x *Exit) {
	p.Dead, p.exited, p.Exact = true, true, !x.Approx
	p.End = x.T
	p.Own = math.Max(0, x.CPU-p.own0)
	p.Cum = p.Own + x.CPUChildren
	p.Final = nil
	p.Unseen = 0
	if x.MaxRss > 0 {
		p.HWM = x.MaxRss
	}
	p.IO = map[string]int64{}
	for _, k := range ioKeys {
		if v, ok := x.IO[k]; ok {
			p.IO[k] = max(0, v-p.io0[k])
		}
	}
	p.Code, p.Signal = x.Code, x.Signal
	p.Reaper = x.Ppid
}

func r3(x float64) float64 { return math.Round(x*1000) / 1000 }
func r4(x float64) float64 { return math.Round(x*10000) / 10000 }

func (p *TP) view() map[string]any {
	cpu := p.Cum
	if p.Final != nil {
		cpu = *p.Final
	}
	peak := p.HWM
	if peak == 0 {
		peak = p.RSSMax
	}
	out := map[string]any{"pid": p.Pid, "ppid": p.Ppid, "depth": p.Depth, "label": p.Label,
		"argv": p.Argv, "startedAt": r3(p.Started), "endedAt": nil, "cpuOwn": r4(p.Own),
		"cpu": r4(cpu), "peakRss": peak, "rss": nil, "threads": p.Threads, "via": p.Via}
	if p.End > 0 {
		out["endedAt"] = r3(p.End)
	}
	if !p.Dead {
		out["rss"] = p.RSS
	}
	if p.exited {
		out["exact"] = p.Exact // false: read after its parent reaped it — the last sample
	}
	if p.Code != nil {
		out["exitCode"] = *p.Code
	}
	if p.Signal != nil {
		out["signal"] = *p.Signal
	}
	if p.Unseen > 0.005 {
		out["cpuUnseen"] = r3(p.Unseen)
	}
	if len(p.IO) > 0 {
		out["io"] = p.IO
	}
	if p.GPU > 0 || p.GPUMem > 0 {
		out["gpuS"] = r3(float64(p.GPU) / 1e9)
		out["gpuMem"] = p.GPUMem
	}
	return out
}

// Call is one tool call the probe follows.
type Call struct {
	ev         Event
	norm       string
	tPre       float64
	root       int
	shell      *TP
	procs      []*TP
	gone       float64
	goneIO     map[string]int64
	goneGPU    int64
	peakTree   int64
	overflow   int
	samples    int
	tPost      float64
	durationMs *int64
	ran        string
	bgTask     string
	interrupt  bool
	shellEnd   float64
	nextAt     float64
	emittedAt  float64
	status     string
	exact      bool
	lost0      uint64
}

func (c *Call) age(now float64) float64 { return now - c.tPre }

func (c *Call) interval(now float64) float64 {
	start := c.tPre
	if c.shell != nil {
		start = c.shell.Started
	}
	switch a := now - start; {
	case a < fastS:
		return fastDt
	case a < midS:
		return midDt
	}
	return 1 / Hz
}

func (c *Call) live() []*TP {
	var out []*TP
	for _, p := range c.procs {
		if !p.Dead {
			out = append(out, p)
		}
	}
	return out
}

func (c *Call) find(pid int, started float64) *TP {
	for _, p := range c.procs {
		if p.Pid == pid && math.Abs(p.Started-started) <= matchS {
			return p
		}
	}
	return nil
}

func (c *Call) member(pid int) bool {
	for _, p := range c.procs {
		if p.Pid == pid {
			return true
		}
	}
	return false
}

func (c *Call) totals() map[string]any {
	var cpu float64
	io := map[string]int64{}
	var gpu int64
	if c.exact {
		// every process the call forked is known: sum what each did itself
		var orphans float64
		for _, p := range c.procs {
			cpu += p.Own
			if p != c.shell && p.exited && !c.member(p.Reaper) {
				orphans += p.Own // reaped by init/launchd: not in the shell's child time
			}
			own := map[string]int64{}
			for k, v := range p.IO {
				own[k] = v
			}
			for _, k := range c.procs { // the I/O of the children it reaped is in its counters
				if k.Parent == p && k.Dead && k.Reaper == p.Pid {
					for n, v := range k.IO {
						own[n] -= v
					}
				}
			}
			for n, v := range own {
				io[n] += max(0, v)
			}
			gpu += p.GPU
		}
		// the shell's own exit counts what every child it reaped cost: on
		// macOS that covers a child whose exit was read too late
		if s := c.shell; s != nil && s.exited && s.Exact {
			cpu = math.Max(cpu, s.Cum+orphans)
		}
	} else {
		cpu = c.gone
		for k, v := range c.goneIO {
			io[k] = v
		}
		gpu = c.goneGPU
		for _, p := range c.live() {
			cpu += p.Cum
			for k, v := range p.IO {
				io[k] += v
			}
			gpu += p.GPU
		}
	}
	peak, gmem := c.peakTree, int64(0)
	for _, p := range c.procs {
		peak = max(peak, p.HWM)
		gmem = max(gmem, p.GPUMem)
	}
	return map[string]any{"cpu": r4(cpu), "peakRss": peak, "procs": len(c.procs) + c.overflow,
		"io": io, "gpuS": r3(float64(gpu) / 1e9), "gpuMem": gmem}
}

func (c *Call) record() map[string]any {
	started := c.tPre
	if c.shell != nil {
		started = c.shell.Started
	}
	var ended any
	if c.shellEnd > 0 {
		ended = r3(c.shellEnd)
	} else if c.tPost > 0 && !c.ev.Bg && c.durationMs != nil {
		ended = r3(c.tPre + float64(*c.durationMs)/1000)
	}
	procs := append([]*TP(nil), c.procs...)
	sort.SliceStable(procs, func(i, j int) bool { return procs[i].Started < procs[j].Started })
	views := make([]map[string]any, 0, len(procs))
	for _, p := range procs {
		views = append(views, p.view())
	}
	source := "sampled"
	if c.exact {
		source = "kernel"
	}
	cmd := c.ev.Command
	if len(cmd) > 4000 {
		cmd = cmd[:4000]
	}
	out := map[string]any{
		"v": 1, "tool": orStr(c.ev.Tool, "Bash"), "toolUseId": c.ev.Tid, "sessionId": c.ev.Sid,
		"agentId": nilIfEmpty(c.ev.AgentID), "agentType": nilIfEmpty(c.ev.AgentType),
		"promptId": nilIfEmpty(c.ev.PromptID), "command": cmd, "cwd": nilIfEmpty(c.ev.Cwd),
		"background": c.ev.Bg, "status": c.status, "seen": c.shell != nil, "source": source,
		"preAt": r3(c.tPre), "startedAt": r3(started), "endedAt": ended,
		"shellEndedAt": nil, "durationMs": c.durationMs, "hz": Hz, "samples": c.samples,
		"liveProcs": len(c.live()), "totals": c.totals(), "procs": views,
	}
	if c.shellEnd > 0 {
		out["shellEndedAt"] = r3(c.shellEnd)
	}
	if c.shell != nil && c.shell.Code != nil {
		out["exitCode"] = *c.shell.Code
	}
	if c.shell != nil && c.shell.Signal != nil {
		out["signal"] = *c.shell.Signal
	}
	if c.interrupt {
		out["interrupted"] = true
	}
	if c.ran != "" && NormCommand(c.ran) != c.norm {
		out["ran"] = trim(c.ran, 4000)
	} else if c.ran != "" && c.ran != c.ev.Command {
		out["rewritten"] = true
	}
	if c.bgTask != "" {
		out["backgroundTaskId"] = c.bgTask
	}
	if c.overflow > 0 {
		out["overflow"] = c.overflow
	}
	return out
}

func orStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Probe follows every live call.
type Probe struct {
	Store     *store.Store
	Feed      *Feed // nil: sampled only
	mu        sync.Mutex
	calls     map[string]*Call
	lastPrune float64
	LastEvent float64
}

func New(st *store.Store, feed *Feed) *Probe {
	return &Probe{Store: st, Feed: feed, calls: map[string]*Call{}, LastEvent: nowF()}
}

func (pr *Probe) kernel(now float64) bool { return pr.Feed.Alive(now) }

// Running is how many calls are being followed.
func (pr *Probe) Running() int { pr.mu.Lock(); defer pr.mu.Unlock(); return len(pr.calls) }

// Handle takes one event from the hook.
func (pr *Probe) Handle(ev Event) {
	now := nowF()
	pr.mu.Lock()
	pr.LastEvent = now
	switch ev.E {
	case "pre":
		if ev.Tid != "" && pr.calls[ev.Tid] == nil {
			t := ev.T
			if t == 0 {
				t = now
			}
			pr.calls[ev.Tid] = &Call{ev: ev, norm: NormCommand(ev.Command), tPre: t, nextAt: now,
				status: "starting", goneIO: map[string]int64{}}
		}
		pr.mu.Unlock()
	case "post":
		if c := pr.calls[ev.Tid]; c != nil {
			c.tPost = orF(ev.T, now)
			c.durationMs = ev.DurationMs
			c.interrupt = ev.Interrupted
			c.ran = ev.Command
			c.bgTask = ev.BgTask
			c.nextAt = now // look now: the shell is exiting
		}
		pr.mu.Unlock()
	case "prompt", "stop", "subStart", "subStop", "session":
		pr.mu.Unlock()
		pr.mark(ev, now)
	default:
		pr.mu.Unlock()
	}
}

func orF(x, d float64) float64 {
	if x == 0 {
		return d
	}
	return x
}

func (pr *Probe) mark(ev Event, now float64) {
	at := r3(orF(ev.T, now))
	data := map[string]any{"v": 1, "event": ev.E, "sessionId": ev.Sid, "at": at}
	for k, v := range map[string]string{"promptId": ev.PromptID, "agentId": ev.AgentID,
		"agentType": ev.AgentType, "cwd": ev.Cwd, "effort": ev.Effort, "configDir": ev.ConfigDir} {
		if v != "" {
			data[k] = v
		}
	}
	if p := plan.Of(ev.ConfigDir); p != nil {
		data["plan"] = p
	}
	if u := pr.usage(ev.ConfigDir); u != nil {
		data["usage"] = u
	}
	if ev.BgTasks != nil {
		data["backgroundTasks"] = *ev.BgTasks
	}
	key := ev.Sid + ":" + ev.E + ":" + ev.PromptID + ":" + ev.AgentID + ":" + strconv.FormatFloat(at, 'f', 3, 64)
	_ = pr.Store.Put("mark", ev.Sid, key, data)
}

// usage is the freshest official reading: what the status line recorded
// (`claude-probe statusline`), or a rate-limits.json some hosts persist.
func (pr *Probe) usage(configDir string) map[string]any {
	file := plan.FileReading(configDir)
	var rec map[string]any
	if r := pr.Store.Newest("usage", plan.ConfigDir(configDir)); r != nil {
		_ = json.Unmarshal(r.Data, &rec)
	}
	if rec == nil {
		return file
	}
	if file == nil {
		return rec
	}
	if f, ok := file["updatedAt"].(float64); ok {
		if g, ok := rec["updatedAt"].(float64); ok && f > g {
			return file
		}
	}
	return rec
}

// Tick looks at every call that is due; returns when the next one is.
func (pr *Probe) Tick() float64 {
	now := nowF()
	pr.mu.Lock()
	calls := make([]*Call, 0, len(pr.calls))
	for _, c := range pr.calls {
		calls = append(calls, c)
	}
	pr.mu.Unlock()
	next := now + 1
	for _, c := range calls {
		if c.nextAt > now {
			next = math.Min(next, c.nextAt)
			continue
		}
		pr.look(c, now)
		pr.mu.Lock()
		_, still := pr.calls[c.ev.Tid]
		pr.mu.Unlock()
		if still {
			c.nextAt = now + c.interval(now)
			next = math.Min(next, c.nextAt)
		}
	}
	if now-pr.lastPrune > 3600 {
		pr.lastPrune = now
		_ = pr.Store.Prune()
	}
	return next
}

// rootOf finds the session's claude: the nearest ancestor of the hook whose
// program is claude, else the one the CLI's session registry names.
func (pr *Probe) rootOf(c *Call) int {
	for _, pid := range c.ev.Chain {
		argv := argvOf(pid)
		if len(argv) == 0 {
			continue
		}
		prog := filepath.Base(argv[0])
		if prog == "claude" {
			return pid
		}
		if prog == "node" || prog == "bun" {
			for _, a := range argv[1:min(3, len(argv))] {
				if b := filepath.Base(a); b == "claude" || b == "cli.js" {
					return pid
				}
			}
		}
	}
	reg := filepath.Join(plan.ConfigDir(c.ev.ConfigDir), "sessions")
	ents, _ := os.ReadDir(reg)
	for _, e := range ents {
		var d struct {
			Pid       int    `json:"pid"`
			SessionID string `json:"sessionId"`
		}
		raw, err := os.ReadFile(filepath.Join(reg, e.Name()))
		if err != nil || json.Unmarshal(raw, &d) != nil || d.SessionID != c.ev.Sid {
			continue
		}
		for _, p := range c.ev.Chain {
			if p == d.Pid {
				return p
			}
		}
	}
	return 0
}

type cand struct {
	pid     int
	started float64
	cmd     string
	bp      *BP
	st      *Stat
}

func (pr *Probe) taken(pid int, started float64) bool {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	for _, x := range pr.calls {
		if x.shell != nil && x.shell.Pid == pid && math.Abs(x.shell.Started-started) <= matchS {
			return true
		}
	}
	return false
}

func (pr *Probe) candidates(c *Call, now float64) []cand {
	var out []cand
	if pr.kernel(now) {
		for _, bp := range pr.Feed.Children(c.root, c.tPre-1, 0) {
			if pr.taken(bp.Pid, bp.Start) {
				continue
			}
			cmd := ToolCommand(bp.Argv)
			var st *Stat
			if cmd == "" && bp.Exit == nil { // a long command line the kernel cut
				if s := readStat(bp.Pid); s != nil && math.Abs(s.Started-bp.Start) <= matchS {
					st = s
					cmd = ToolCommand(argvOf(bp.Pid))
				}
			}
			if cmd != "" {
				b := bp
				out = append(out, cand{bp.Pid, bp.Start, cmd, &b, st})
			}
		}
		return out
	}
	for _, pid := range children(c.root) {
		st := readStat(pid)
		if st == nil || st.Started < c.tPre-1 || pr.taken(pid, st.Started) {
			continue
		}
		cmd := ToolCommand(argvOf(pid))
		if cmd == "" { // a sandbox wrapper (bwrap) one level up
			for _, k := range children(pid) {
				if cmd = ToolCommand(argvOf(k)); cmd != "" {
					break
				}
			}
		}
		if cmd != "" {
			out = append(out, cand{pid, st.Started, cmd, nil, st})
		}
	}
	return out
}

func (pr *Probe) findShell(c *Call, now float64) {
	if c.root == 0 {
		c.root = pr.rootOf(c)
		if c.root != 0 && pr.Feed != nil {
			pr.Feed.EnsureRoot(c.root)
		}
	}
	if c.root == 0 {
		return
	}
	cands := pr.candidates(c, now)
	if len(cands) == 0 {
		return
	}
	var pick *cand
	for i := range cands {
		if NormCommand(cands[i].cmd) == c.norm && (pick == nil || cands[i].started < pick.started) {
			pick = &cands[i]
		}
	}
	if pick == nil {
		// first in, first out among this process's waiting calls whose
		// command matched no shell (rtk rewrote more than a prefix)
		pr.mu.Lock()
		var waiting []*Call
		for _, x := range pr.calls {
			if x.shell == nil && x.root == c.root {
				waiting = append(waiting, x)
			}
		}
		pr.mu.Unlock()
		sort.Slice(waiting, func(i, j int) bool { return waiting[i].tPre < waiting[j].tPre })
		names := map[string]bool{}
		for _, x := range cands {
			names[NormCommand(x.cmd)] = true
		}
		var unmatched []*Call
		for _, w := range waiting {
			if !names[w.norm] {
				unmatched = append(unmatched, w)
			}
		}
		if len(unmatched) == 0 || unmatched[0] != c {
			return
		}
		norms := map[string]bool{}
		for _, w := range waiting {
			norms[w.norm] = true
		}
		for i := range cands {
			if !norms[NormCommand(cands[i].cmd)] && (pick == nil || cands[i].started < pick.started) {
				pick = &cands[i]
			}
		}
		if pick == nil {
			return
		}
	}
	var tp *TP
	if pick.bp != nil {
		tp = tpFromKernel(*pick.bp, nil, 0)
		c.exact = pr.Feed.Since() > 0 && pr.Feed.Since() <= c.tPre
		c.lost0 = pr.Feed.Lost()
	} else {
		tp = tpFromProc(pick.pid, pick.st, nil, "tree", 0, true)
		c.exact = false
	}
	c.procs = append(c.procs, tp)
	c.shell = tp
	c.status = "running"
}

func (pr *Probe) look(c *Call, now float64) {
	if c.shell == nil {
		pr.findShell(c, now)
		if c.shell == nil {
			if now-c.tPre > findTimeoutS {
				log.Printf("%s: no shell found (root %d, kernel layer %v, chain %v)",
					c.ev.Tid, c.root, pr.kernel(now), c.ev.Chain)
				if c.tPost > 0 { // it ran, too quick to see
					c.status = "done"
					pr.emit(c, now)
				}
				pr.drop(c)
			}
			return
		}
	}
	c.samples++
	kernel := c.exact && pr.kernel(now)
	if c.exact && (!kernel || pr.Feed.Lost() != c.lost0) {
		c.exact, kernel = false, false // the kernel layer went quiet or lost events mid-call
	}
	// every death first, so a parent's reaped-CPU growth finds the
	// children that explain it
	var died []*TP
	type pair struct {
		p  *TP
		st *Stat
	}
	var alive []pair
	for _, p := range c.live() {
		st := readStat(p.Pid)
		if st == nil || math.Abs(st.Started-p.Started) > matchS {
			p.Dead = true
			if p.End == 0 {
				p.End = now - c.interval(now)/2
			}
			died = append(died, p)
		} else {
			alive = append(alive, pair{p, st})
		}
	}
	for _, a := range alive {
		prev := a.p.Cum - a.p.Own
		a.p.update(a.st, now)
		if !kernel {
			reaped(c, a.p, prev)
		}
	}
	if kernel {
		pr.growKernel(c)
	} else {
		pr.growProc(c, now)
	}
	live := c.live()
	var tree int64
	for _, p := range live {
		tree += p.RSS
	}
	c.peakTree = max(c.peakTree, tree)
	if !kernel {
		// a dead process whose parent we don't follow (the shell, reaped by
		// claude; an orphan, reaped by init) takes its last cost along
		for _, d := range died {
			if d.Parent == nil || d.Parent.Dead || d.Parent.Pid != d.Ppid {
				if d.Final != nil {
					c.gone += *d.Final
				} else {
					c.gone += d.Cum
				}
				for k, v := range d.IO {
					c.goneIO[k] += v
				}
				c.goneGPU += d.GPU
			}
		}
	}
	if c.shell.Dead && c.shellEnd == 0 {
		c.shellEnd = c.shell.End
	}
	pending := false
	if kernel {
		for _, p := range c.procs {
			if p.Dead && !p.exited {
				pending = true
			}
		}
	}
	if c.shell.Dead && c.status == "running" && !pending {
		if len(live) > 0 {
			c.status = "detached"
		} else {
			c.status = "done"
		}
		pr.emit(c, now)
	}
	if len(live) == 0 && !pending {
		if c.tPost > 0 || now-orF(c.shellEnd, now) > 3 {
			if c.status != "error" && c.status != "capped" {
				c.status = "done"
			}
			pr.finish(c, now)
		}
		return
	}
	if len(live) == 0 && pending && now-orF(c.shellEnd, now) > 3 {
		c.exact = false // an exit never arrived (lost): what we have is sampled
		c.status = "done"
		pr.finish(c, now)
		return
	}
	if c.age(now) > BgCapS {
		c.status = "capped"
		pr.finish(c, now)
		return
	}
	if now-c.emittedAt >= runningEvery && c.age(now) >= runningEvery {
		pr.emit(c, now)
	}
}

// growKernel adds members from the kernel's fork tree; exact exits for the dead.
func (pr *Probe) growKernel(c *Call) {
	queue := append([]*TP(nil), c.procs...)
	for len(queue) > 0 {
		p := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		bp := pr.Feed.Find(p.Pid, p.Started)
		if bp != nil && len(bp.Argv) > 0 && joinArgv(bp.Argv) != p.raw && p.Depth > 0 {
			p.setArgv(bp.Argv, bp.Comm) // it exec'd since we saw it
		}
		if bp != nil && bp.Exit != nil && !p.exited {
			p.applyExit(bp.Exit)
		}
		end := 0.0
		if p.Dead {
			end = p.End
		}
		for _, k := range pr.Feed.Children(p.Pid, p.Started, end) {
			if c.find(k.Pid, k.Start) != nil {
				continue
			}
			if len(c.procs) >= maxProcs {
				c.overflow++
				continue
			}
			tp := tpFromKernel(k, p, p.Depth+1)
			c.procs = append(c.procs, tp)
			queue = append(queue, tp)
		}
	}
}

// growProc adds members from /proc: the children of every live member.
func (pr *Probe) growProc(c *Call, now float64) {
	frontier := c.live()
	for len(frontier) > 0 {
		var next []*TP
		for _, p := range frontier {
			for _, k := range children(p.Pid) {
				st := readStat(k)
				if st == nil || c.find(k, st.Started) != nil {
					continue
				}
				if len(c.procs) >= maxProcs {
					c.overflow++
					continue
				}
				tp := tpFromProc(k, st, p, "tree", p.Depth+1, st.Started >= c.tPre-1)
				c.procs = append(c.procs, tp)
				next = append(next, tp)
			}
		}
		frontier = next
	}
}

// reaped (sampled only) splits the growth of p's reaped-children CPU between
// the children of p that died since the last look; what none explains ran
// and exited unseen.
func reaped(c *Call, p *TP, prev float64) {
	grown := (p.Cum - p.Own) - prev
	if grown <= 0.0005 {
		return
	}
	var kids []*TP
	var seen float64
	for _, k := range c.procs {
		if k.Parent == p && k.Dead && k.Final == nil {
			kids = append(kids, k)
			seen += k.Cum
		}
	}
	if len(kids) == 0 {
		p.Unseen += grown
		return
	}
	extra := math.Max(0, grown-seen)
	for _, k := range kids {
		share := extra / float64(len(kids))
		if seen > 0 {
			share = extra * (k.Cum / seen)
		}
		f := k.Cum + share
		k.Final = &f
	}
}

func (pr *Probe) emit(c *Call, now float64) {
	c.emittedAt = now
	_ = pr.Store.Put("call", c.ev.Sid, c.ev.Tid, c.record())
}

func (pr *Probe) finish(c *Call, now float64) {
	pr.emit(c, now)
	pr.drop(c)
}

func (pr *Probe) drop(c *Call) {
	pr.mu.Lock()
	delete(pr.calls, c.ev.Tid)
	pr.mu.Unlock()
}
