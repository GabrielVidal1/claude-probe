//go:build darwin

package probe

import (
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"
)

// macOS has no /proc: the process table from one sysctl, per-process CPU
// and memory through gopsutil (libproc, no cgo). No peak-RSS, I/O or GPU
// counters there — the probe keeps the sampled maximum.

var (
	tableMu sync.Mutex
	tableAt time.Time
	table   map[int]unix.KinfoProc
)

func procTable() map[int]unix.KinfoProc {
	tableMu.Lock()
	defer tableMu.Unlock()
	if table != nil && time.Since(tableAt) < 20*time.Millisecond {
		return table
	}
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return table
	}
	t := make(map[int]unix.KinfoProc, len(kps))
	for _, k := range kps {
		t[int(k.Proc.P_pid)] = k
	}
	table, tableAt = t, time.Now()
	return t
}

func BootNsToEpoch(ns uint64) float64 { return 0 }

func readStat(pid int) *Stat {
	// one fresh sysctl: the cached table can be 20 ms old, and a process
	// born since would read as gone
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil || kp.Proc.P_pid != int32(pid) || kp.Proc.P_stat == 5 { // SZOMB
		return nil
	}
	k := *kp
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return nil
	}
	started := float64(k.Proc.P_starttime.Sec) + float64(k.Proc.P_starttime.Usec)/1e6
	out := &Stat{Ppid: int(k.Eproc.Ppid), Start: started, Started: started,
		Comm: unix.ByteSliceToString(k.Proc.P_comm[:]), IO: map[string]int64{}}
	if t, err := p.Times(); err == nil {
		out.Own = t.User + t.System
		out.Cum = out.Own
	}
	if m, err := p.MemoryInfo(); err == nil {
		out.RSS = int64(m.RSS)
	}
	if n, err := p.NumThreads(); err == nil {
		out.Threads = int(n)
	}
	return out
}

func children(pid int) []int {
	var out []int
	for p, k := range procTable() {
		if int(k.Eproc.Ppid) == pid {
			out = append(out, p)
		}
	}
	return out
}

func argvOf(pid int) []string {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return nil
	}
	a, _ := p.CmdlineSlice()
	return a
}

func drmFds(int) []string                      { return nil }
func gpuOf(int, []string) (int64, int64, bool) { return 0, 0, false }
func startKey(s *Stat) float64                 { return s.Start }

func ProcList() map[int]int {
	out := map[int]int{}
	for p, k := range procTable() {
		out[p] = int(k.Eproc.Ppid)
	}
	return out
}

func Comm(pid int) string {
	if k, ok := procTable()[pid]; ok {
		return unix.ByteSliceToString(k.Proc.P_comm[:])
	}
	return ""
}

func UID(pid int) int {
	if k, ok := procTable()[pid]; ok {
		return int(k.Eproc.Ucred.Uid)
	}
	return -1
}

func ParentOf(pid int) int {
	if k, ok := procTable()[pid]; ok {
		return int(k.Eproc.Ppid)
	}
	return 0
}
