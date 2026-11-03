package probe

import (
	"math"
	"sync"
	"time"
)

// Stat is one process as one look at /proc (or libproc) saw it. Own = its
// own CPU seconds, Cum = own + its reaped children's; IO is cumulative too
// (the kernel adds a reaped child's I/O to its parent's).
type Stat struct {
	Ppid     int
	Start    float64 // the platform's start fingerprint
	Started  float64 // epoch seconds
	Comm     string
	Own, Cum float64
	RSS, HWM int64
	Threads  int
	IO       map[string]int64
}

func nowF() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// Exit is what the kernel reported when a process exited.
type Exit struct {
	T, Start    float64
	Ppid        int
	Code        *int
	Signal      *int
	CPU         float64
	CPUChildren float64
	MaxRss      int64
	IO          map[string]int64
	Approx      bool // macOS: reaped before it could be read — the last sample
}

// BP is a process as the kernel layer saw it: fork parent, latest exec, exit.
type BP struct {
	Pid, Ppid int
	Start     float64
	Argv      []string
	Comm      string
	Exit      *Exit
}

const (
	matchS = 0.5   // a /proc start-time vs the kernel's
	slackS = 0.05  //
	keepS  = 1800. // exited processes kept this long for calls to collect
	staleS = 75.0  // the kernel layer's heartbeat window
)

// Feed is the kernel layer's table of every process under an agent. The
// reader goroutine writes it; the probe reads it.
type Feed struct {
	mu     sync.Mutex
	byPid  map[int][]*BP
	kids   map[int][]*BP
	hbAt   float64
	since  float64
	lost   uint64
	pruned float64
	// OnRoot asks the layer to follow an agent it didn't find by itself (a
	// node-run claude); the probe calls it with each call's root.
	OnRoot func(pid int)
	roots  map[int]bool
}

func NewFeed() *Feed {
	return &Feed{byPid: map[int][]*BP{}, kids: map[int][]*BP{}, roots: map[int]bool{}}
}

// EnsureRoot tells the layer, once per process, to follow this agent.
func (f *Feed) EnsureRoot(pid int) {
	if f == nil {
		return
	}
	f.mu.Lock()
	seen := f.roots[pid]
	f.roots[pid] = true
	cb := f.OnRoot
	f.mu.Unlock()
	if !seen && cb != nil {
		cb(pid)
	}
}

// Beat marks the kernel layer alive (since = when it started).
func (f *Feed) Beat(since float64, lost uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hbAt = nowF()
	if f.since == 0 || since < f.since {
		f.since = since
	}
	f.lost = lost
}

func (f *Feed) Stop() {
	f.mu.Lock()
	f.hbAt = 0
	f.mu.Unlock()
}

func (f *Feed) Alive(now float64) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return now-f.hbAt < staleS
}

func (f *Feed) Since() float64 { f.mu.Lock(); defer f.mu.Unlock(); return f.since }
func (f *Feed) Lost() uint64   { f.mu.Lock(); defer f.mu.Unlock(); return f.lost }

func (f *Feed) latest(pid int) *BP {
	v := f.byPid[pid]
	if len(v) == 0 {
		return nil
	}
	return v[len(v)-1]
}

func (f *Feed) add(bp *BP) {
	f.byPid[bp.Pid] = append(f.byPid[bp.Pid], bp)
	f.kids[bp.Ppid] = append(f.kids[bp.Ppid], bp)
}

func (f *Feed) Fork(pid, ppid int, t float64, comm string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.add(&BP{Pid: pid, Ppid: ppid, Start: t, Comm: comm})
}

// Exec records a new image; seed = a process already running when the layer
// started (from /proc).
func (f *Feed) Exec(pid, ppid int, start float64, comm string, argv []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	bp := f.latest(pid)
	if bp == nil || bp.Exit != nil || math.Abs(bp.Start-start) > matchS {
		bp = &BP{Pid: pid, Ppid: ppid, Start: start}
		f.add(bp)
	}
	if len(argv) > 0 {
		bp.Argv = argv
	}
	if comm != "" {
		bp.Comm = comm
	}
}

func (f *Feed) ExitEv(pid int, x *Exit) {
	f.mu.Lock()
	defer f.mu.Unlock()
	bp := f.latest(pid)
	if bp == nil || bp.Exit != nil {
		bp = &BP{Pid: pid, Ppid: x.Ppid, Start: x.Start}
		f.add(bp)
	}
	bp.Exit = x
	if now := nowF(); now-f.pruned > 60 {
		f.pruned = now
		f.prune(now)
	}
}

// Children are the processes forked by pid while that incarnation lived.
func (f *Feed) Children(pid int, start float64, end float64) []BP {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []BP
	for _, k := range f.kids[pid] {
		if k.Start >= start-slackS && (end == 0 || k.Start <= end+slackS) {
			out = append(out, *k)
		}
	}
	return out
}

func (f *Feed) Find(pid int, started float64) *BP {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.byPid[pid]
	for i := len(v) - 1; i >= 0; i-- {
		if math.Abs(v[i].Start-started) <= matchS {
			c := *v[i]
			return &c
		}
	}
	return nil
}

func (f *Feed) prune(now float64) {
	gone := func(b *BP) bool { return b.Exit != nil && b.Exit.T < now-keepS }
	for _, table := range []map[int][]*BP{f.byPid, f.kids} {
		for k, v := range table {
			keep := v[:0]
			for _, b := range v {
				if !gone(b) {
					keep = append(keep, b)
				}
			}
			if len(keep) == 0 {
				delete(table, k)
			} else {
				table[k] = keep
			}
		}
	}
}
