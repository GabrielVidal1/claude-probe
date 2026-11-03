//go:build darwin

package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// The macOS event layer — no root, no setup. kqueue's EVFILT_PROC delivers
// fork, exec and exit (with the real exit status, NOTE_EXITSTATUS) for any
// process of the same user, not only children — grandchildren and daemons
// launchd adopted included (undocumented, verified on macOS 26; StartKernel
// self-tests it). NOTE_FORK carries no child pid, so each fork lists the
// parent's children (proc_listchildpids) and watches the new ones.
//
// What a process cost comes from proc_pid_rusage, which still answers for a
// zombie: read on NOTE_EXIT it gives the exact CPU, lifetime peak footprint
// and disk I/O — unless the parent reaped it first; then the last sample
// (every SampleEvery) stands, flagged approximate.

var SampleEvery = 20 * time.Millisecond

var (
	libOnce          sync.Once
	libErr           error
	procPidRusage    func(pid int32, flavor int32, buf unsafe.Pointer) int32
	procListChildren func(ppid int32, buf unsafe.Pointer, size int32) int32
	machTimebase     func(info unsafe.Pointer) int32
	setQoS           func(class uint32, prio int32) int32
	tbNumer, tbDenom uint64 = 1, 1
)

func loadLib() error {
	libOnce.Do(func() {
		h, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			libErr = err
			return
		}
		purego.RegisterLibFunc(&procPidRusage, h, "proc_pid_rusage")
		purego.RegisterLibFunc(&procListChildren, h, "proc_listchildpids")
		purego.RegisterLibFunc(&machTimebase, h, "mach_timebase_info")
		purego.RegisterLibFunc(&setQoS, h, "pthread_set_qos_class_self_np")
		var tb [2]uint32
		if machTimebase(unsafe.Pointer(&tb[0])) == 0 && tb[1] != 0 {
			tbNumer, tbDenom = uint64(tb[0]), uint64(tb[1])
		}
	})
	return libErr
}

// rusage is what proc_pid_rusage (RUSAGE_INFO_V4) gives.
type rusage struct {
	cpu, childCPU float64 // seconds
	peak          int64   // lifetime max physical footprint
	rbytes, wbytes int64
}

func readRusage(pid int) (rusage, bool) {
	var buf [512]byte
	if procPidRusage(int32(pid), 4, unsafe.Pointer(&buf[0])) != 0 {
		return rusage{}, false
	}
	u := func(i int) uint64 { return binary.LittleEndian.Uint64(buf[16+8*i:]) }
	toS := func(abs uint64) float64 { return float64(abs*tbNumer/tbDenom) / 1e9 }
	return rusage{cpu: toS(u(0) + u(1)), childCPU: toS(u(10) + u(11)), peak: int64(u(28)),
		rbytes: int64(u(16)), wbytes: int64(u(17))}, true
}

func childPids(pid int) []int {
	var buf [1024]int32
	// proc_listchildpids returns a count of pids (proc_listpids, bytes)
	n := procListChildren(int32(pid), unsafe.Pointer(&buf[0]), int32(len(buf)*4))
	if n <= 0 {
		return nil
	}
	out := make([]int, 0, n)
	for _, p := range buf[:min(int(n), len(buf))] {
		if p > 0 {
			out = append(out, int(p))
		}
	}
	return out
}

// procArgs reads a process's argv (KERN_PROCARGS2: argc, exec path, argv).
func procArgs(pid int) []string {
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(raw) < 4 {
		return nil
	}
	argc := int(binary.LittleEndian.Uint32(raw))
	rest := raw[4:]
	i := 0
	for i < len(rest) && rest[i] != 0 { // the exec path
		i++
	}
	for i < len(rest) && rest[i] == 0 {
		i++
	}
	var out []string
	for len(out) < argc && i < len(rest) {
		j := i
		for j < len(rest) && rest[j] != 0 {
			j++
		}
		out = append(out, string(rest[i:j]))
		i = j + 1
	}
	return out
}

type watched struct {
	start float64
	last  rusage
	seen  bool
}

// Kernel is the running event layer.
type Kernel struct {
	kq    int
	feed  *Feed
	uid   int
	mu    sync.Mutex
	procs map[int]*watched
	stop  chan struct{}
	once  sync.Once
	Notes []string
}

func StartKernel(feed *Feed, uid uint32) (*Kernel, error) {
	if err := loadLib(); err != nil {
		return nil, err
	}
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, err
	}
	k := &Kernel{kq: kq, feed: feed, uid: int(uid), procs: map[int]*watched{}, stop: make(chan struct{})}
	if err := k.selfTest(); err != nil {
		unix.Close(kq)
		return nil, err
	}
	since := nowF()
	k.seed()
	feed.Beat(since, 0)
	feed.OnRoot = k.addRoot
	go k.loop()
	go k.sample(since)
	return k, nil
}

func (k *Kernel) Close() {
	k.once.Do(func() {
		close(k.stop)
		unix.Close(k.kq)
		k.feed.Stop()
	})
}

// selfTest checks that kqueue reports a grandchild's exit status (the
// undocumented behaviour the layer stands on).
func (k *Kernel) selfTest() error {
	kq, err := unix.Kqueue()
	if err != nil {
		return err
	}
	defer unix.Close(kq)
	pid, err := forkExit()
	if err != nil {
		return nil // can't test; trust it
	}
	var ch [1]unix.Kevent_t
	unix.SetKevent(&ch[0], pid, unix.EVFILT_PROC, unix.EV_ADD)
	ch[0].Fflags = unix.NOTE_EXIT | unix.NOTE_EXITSTATUS
	if _, err := unix.Kevent(kq, ch[:], nil, nil); err != nil {
		return nil // it exited before we could attach: inconclusive
	}
	ev := make([]unix.Kevent_t, 1)
	ts := unix.NsecToTimespec(int64(2 * time.Second))
	if n, _ := unix.Kevent(kq, nil, ev, &ts); n == 1 && (ev[0].Data>>8)&0xff == 7 {
		return nil
	}
	return errors.New("kqueue gave no exit status for a non-child: sampling instead")
}

// isRoot: an agent of ours. The native claude's comm can be its version
// ("2.1.309": it runs from versions/<v>), so argv[0] decides.
func (k *Kernel) isRoot(pid int) bool {
	if UID(pid) != k.uid {
		return false
	}
	a := procArgs(pid)
	if Comm(pid) == "claude" || (len(a) > 0 && baseName(a[0]) == "claude") {
		return true
	}
	return len(a) > 1 && (Comm(pid) == "node" || Comm(pid) == "bun") &&
		(baseName(a[1]) == "claude" || baseName(a[1]) == "cli.js")
}

func baseName(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return s[i+1:]
		}
	}
	return s
}

// seed watches the agents running now and everything under them; run again
// every second to find new agents (an exec of `claude` gives no event to a
// process not watched yet).
func (k *Kernel) seed() {
	parent := ProcList()
	kids := map[int][]int{}
	for p, pp := range parent {
		kids[pp] = append(kids[pp], p)
	}
	var stack []int
	for p := range parent {
		k.mu.Lock()
		_, known := k.procs[p]
		k.mu.Unlock()
		if !known && k.isRoot(p) {
			stack = append(stack, p)
		}
	}
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		k.watch(p, parent[p])
		stack = append(stack, kids[p]...)
	}
}

func (k *Kernel) addRoot(pid int) {
	if UID(pid) == k.uid {
		k.watch(pid, ParentOf(pid))
		for _, c := range childPids(pid) {
			k.watch(c, pid)
		}
	}
}

func startOf(pid int) float64 {
	if kp, ok := procTable()[pid]; ok {
		return float64(kp.Proc.P_starttime.Sec) + float64(kp.Proc.P_starttime.Usec)/1e6
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0
	}
	return float64(kp.Proc.P_starttime.Sec) + float64(kp.Proc.P_starttime.Usec)/1e6
}

// watch attaches to one process (fork, exec, exit) and records it.
func (k *Kernel) watch(pid, ppid int) {
	k.mu.Lock()
	if _, ok := k.procs[pid]; ok {
		k.mu.Unlock()
		return
	}
	w := &watched{start: startOf(pid)}
	k.procs[pid] = w
	k.mu.Unlock()
	var ch [1]unix.Kevent_t
	unix.SetKevent(&ch[0], pid, unix.EVFILT_PROC, unix.EV_ADD)
	ch[0].Fflags = unix.NOTE_EXIT | unix.NOTE_EXITSTATUS | unix.NOTE_FORK | unix.NOTE_EXEC
	if _, err := unix.Kevent(k.kq, ch[:], nil, nil); err != nil {
		k.mu.Lock()
		delete(k.procs, pid)
		k.mu.Unlock()
		return
	}
	k.feed.Fork(pid, ppid, w.start, Comm(pid))
	k.feed.Exec(pid, ppid, w.start, Comm(pid), procArgs(pid))
	for _, c := range childPids(pid) { // children forked before we attached
		k.watch(c, pid)
	}
}

// loop reads kqueue on its own OS thread at user-interactive QoS: a zombie's
// rusage is readable only until its parent reaps it, so every exit in a batch
// is read before anything else is done.
func (k *Kernel) loop() {
	runtime.LockOSThread()
	if setQoS != nil {
		setQoS(0x21, 0) // QOS_CLASS_USER_INTERACTIVE
	}
	evs := make([]unix.Kevent_t, 256)
	type gone struct {
		pid, status int
		ru          rusage
		ok          bool
	}
	for {
		select {
		case <-k.stop:
			return
		default:
		}
		ts := unix.NsecToTimespec(int64(time.Second))
		n, err := unix.Kevent(k.kq, nil, evs, &ts)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		var exits []gone
		for _, ev := range evs[:n] { // 1. the exits' rusage, while they are zombies
			if ev.Fflags&unix.NOTE_EXIT != 0 {
				ru, ok := readRusage(int(ev.Ident))
				exits = append(exits, gone{int(ev.Ident), int(ev.Data), ru, ok})
			}
		}
		for _, ev := range evs[:n] { // 2. forks and execs
			pid := int(ev.Ident)
			if ev.Fflags&unix.NOTE_FORK != 0 {
				for _, c := range childPids(pid) {
					k.watch(c, pid)
				}
			}
			if ev.Fflags&unix.NOTE_EXEC != 0 {
				k.mu.Lock()
				w := k.procs[pid]
				k.mu.Unlock()
				if w != nil {
					k.feed.Exec(pid, ParentOf(pid), w.start, Comm(pid), procArgs(pid))
				}
			}
		}
		for _, x := range exits { // 3. the exits themselves
			k.exited(x.pid, x.status, x.ru, x.ok)
		}
	}
}

func (k *Kernel) exited(pid, status int, ru rusage, ok bool) {
	k.mu.Lock()
	w := k.procs[pid]
	delete(k.procs, pid)
	k.mu.Unlock()
	if w == nil {
		return
	}
	x := &Exit{T: nowF(), Start: w.start, Ppid: ParentOf(pid)}
	if !ok {
		ru, x.Approx = w.last, true // reaped first: the last sample stands
	}
	x.CPU, x.CPUChildren, x.MaxRss = ru.cpu, ru.childCPU, ru.peak
	x.IO = map[string]int64{"read_bytes": ru.rbytes, "write_bytes": ru.wbytes}
	if status&0x7f != 0 {
		s := status & 0x7f
		x.Signal = &s
	} else {
		c := (status >> 8) & 0xff
		x.Code = &c
	}
	k.feed.ExitEv(pid, x)
}

// sample keeps the last rusage of every live process (the fallback when a
// parent reaps before NOTE_EXIT is read), re-seeds, and beats.
func (k *Kernel) sample(since float64) {
	t := time.NewTicker(SampleEvery)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case <-k.stop:
			return
		case <-t.C:
		}
		k.mu.Lock()
		pids := make([]int, 0, len(k.procs))
		for p := range k.procs {
			pids = append(pids, p)
		}
		k.mu.Unlock()
		for _, p := range pids {
			if ru, ok := readRusage(p); ok {
				k.mu.Lock()
				if w := k.procs[p]; w != nil {
					w.last, w.seen = ru, true
				}
				k.mu.Unlock()
			}
		}
		if time.Since(last) >= time.Second {
			last = time.Now()
			k.seed()
			k.feed.Beat(since, 0)
		}
	}
}

// forkExit starts a process that isn't ours (a grandchild of this one)
// exiting with 7 after a short sleep, and returns its pid.
func forkExit() (int, error) {
	cmd := exec.Command("/bin/sh", "-c", "(sleep 0.3; exit 7) & echo $!; wait")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	go func() { _ = cmd.Wait() }()
	var gp int
	_, err = fmt.Fscanf(out, "%d", &gp)
	return gp, err
}
