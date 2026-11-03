//go:build linux

package probe

import (
	"bytes"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var (
	clkTck   = 100.0 // USER_HZ: 100 on every Linux the probe targets
	pageSize = int64(os.Getpagesize())
	bootAt   = bootEpoch()
)

// bootEpoch: /proc start times count clock ticks since boot; `btime` has a
// 1-s grain, the boot clock doesn't — the kernel's times and ours agree.
func bootEpoch() float64 {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) == nil {
		return nowF() - float64(ts.Sec) - float64(ts.Nsec)/1e9
	}
	return 0
}

// BootNsToEpoch converts a CLOCK_BOOTTIME nanosecond stamp (the kernel
// program's) to epoch seconds.
func BootNsToEpoch(ns uint64) float64 {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) != nil {
		return 0
	}
	nowBoot := float64(ts.Sec) + float64(ts.Nsec)/1e9
	return nowF() - (nowBoot - float64(ns)/1e9)
}

func readFile(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

// readStat reads one process: /proc/<pid>/stat, status (VmHWM) and io.
func readStat(pid int) *Stat {
	raw := readFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if raw == nil {
		return nil
	}
	s := string(raw)
	open, close := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || close < open || close+2 > len(s) {
		return nil
	}
	f := strings.Fields(s[close+2:])
	if len(f) < 22 || f[0] == "Z" || f[0] == "X" {
		return nil
	}
	n := func(i int) float64 { v, _ := strconv.ParseFloat(f[i], 64); return v }
	ppid, _ := strconv.Atoi(f[1])
	ut, st, cut, cst := n(11), n(12), n(13), n(14)
	start := n(19)
	out := &Stat{
		Ppid: ppid, Start: start, Started: bootAt + start/clkTck, Comm: s[open+1 : close],
		Own: (ut + st) / clkTck, Cum: (ut + st + cut + cst) / clkTck,
		RSS: int64(n(21)) * pageSize, Threads: int(n(17)), IO: map[string]int64{},
	}
	if st := readFile("/proc/" + strconv.Itoa(pid) + "/status"); st != nil {
		if i := bytes.Index(st, []byte("\nVmHWM:")); i >= 0 {
			line := st[i+7:]
			if j := bytes.IndexByte(line, '\n'); j >= 0 {
				line = line[:j]
			}
			kb, _ := strconv.ParseInt(strings.Fields(string(line) + " 0")[0], 10, 64)
			out.HWM = kb * 1024
		}
	}
	if io := readFile("/proc/" + strconv.Itoa(pid) + "/io"); io != nil {
		for _, line := range strings.Split(string(io), "\n") {
			k, v, ok := strings.Cut(line, ": ")
			if ok && (k == "rchar" || k == "wchar" || k == "read_bytes" || k == "write_bytes") {
				x, _ := strconv.ParseInt(v, 10, 64)
				out.IO[k] = x
			}
		}
	}
	return out
}

// children lists a process's children — every thread's `children` file (a Go
// or node program forks from any of its threads).
func children(pid int) []int {
	dir := "/proc/" + strconv.Itoa(pid) + "/task"
	tasks, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []int
	for _, t := range tasks {
		raw := readFile(dir + "/" + t.Name() + "/children")
		for _, x := range strings.Fields(string(raw)) {
			if v, err := strconv.Atoi(x); err == nil {
				out = append(out, v)
			}
		}
	}
	return out
}

func argvOf(pid int) []string {
	raw := readFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	var out []string
	for _, a := range bytes.Split(raw, []byte{0}) {
		if len(a) > 0 {
			out = append(out, string(a))
		}
	}
	return out
}

// drmFds lists the fds of a process that point at a DRM device.
func drmFds(pid int) []string {
	dir := "/proc/" + strconv.Itoa(pid) + "/fd"
	fds, err := os.ReadDir(dir)
	if err != nil || len(fds) > 2000 {
		return nil
	}
	var out []string
	for _, fd := range fds {
		if l, err := os.Readlink(dir + "/" + fd.Name()); err == nil && strings.HasPrefix(l, "/dev/dri/") {
			out = append(out, fd.Name())
		}
	}
	return out
}

// gpuOf sums engine ns and memory bytes over a process's DRM clients
// (drm-client-id dedupes fds sharing one).
func gpuOf(pid int, fds []string) (int64, int64, bool) {
	seen := map[string]bool{}
	var ns, mem int64
	found := false
	for _, fd := range fds {
		raw := readFile("/proc/" + strconv.Itoa(pid) + "/fdinfo/" + fd)
		if raw == nil || !bytes.Contains(raw, []byte("drm-")) {
			continue
		}
		client := ""
		var e, m int64
		for _, line := range strings.Split(string(raw), "\n") {
			k, v, _ := strings.Cut(line, ":")
			v = strings.TrimSpace(v)
			fs := strings.Fields(v)
			switch {
			case k == "drm-client-id":
				client = v
			case strings.HasPrefix(k, "drm-engine-") && !strings.HasPrefix(k, "drm-engine-capacity") && len(fs) > 0:
				x, _ := strconv.ParseInt(fs[0], 10, 64)
				e += x
			case (strings.HasPrefix(k, "drm-memory-") || strings.HasPrefix(k, "drm-resident-")) && len(fs) > 0:
				x, _ := strconv.ParseInt(fs[0], 10, 64)
				unit := int64(1)
				if len(fs) > 1 {
					unit = map[string]int64{"KiB": 1024, "MiB": 1 << 20, "GiB": 1 << 30}[fs[1]]
					if unit == 0 {
						unit = 1
					}
				}
				m += x * unit
			}
		}
		if client != "" && seen[client] {
			continue
		}
		seen[client] = true
		found = true
		ns, mem = ns+e, mem+m
	}
	return ns, mem, found
}

// startMatches compares a /proc start (ticks) to a TP's.
func startKey(s *Stat) float64 { return s.Start }

// ProcList is every process's (pid → ppid) — the kernel layer's seed.
func ProcList() map[int]int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	out := map[int]int{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw := readFile("/proc/" + e.Name() + "/stat")
		s := string(raw)
		close := strings.LastIndexByte(s, ')')
		if close < 0 || close+2 > len(s) {
			continue
		}
		f := strings.Fields(s[close+2:])
		if len(f) > 1 {
			pp, _ := strconv.Atoi(f[1])
			out[pid] = pp
		}
	}
	return out
}

// Comm is a process's short name; UID its real uid.
func Comm(pid int) string {
	return strings.TrimSpace(string(readFile("/proc/" + strconv.Itoa(pid) + "/comm")))
}

func UID(pid int) int {
	raw := readFile("/proc/" + strconv.Itoa(pid) + "/status")
	if i := bytes.Index(raw, []byte("\nUid:")); i >= 0 {
		f := strings.Fields(string(raw[i+5:]))
		if len(f) > 0 {
			u, _ := strconv.Atoi(f[0])
			return u
		}
	}
	return -1
}

// ParentOf is a process's parent (the hook's PID chain).
func ParentOf(pid int) int {
	if s := readStat(pid); s != nil {
		return s.Ppid
	}
	return 0
}
