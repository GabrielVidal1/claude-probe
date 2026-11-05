package storage

import (
	"bufio"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// FS is the filesystem a path lives on.
type FS struct {
	Mount  string `json:"mount"`
	Type   string `json:"fsType"`
	RAM    bool   `json:"ram,omitempty"` // tmpfs/ramfs: its bytes are memory
	Total  int64  `json:"total"`
	Free   int64  `json:"free"`
	Avail  int64  `json:"avail"`
	Device string `json:"device,omitempty"`
}

type mountRow struct{ point, fstype, src string }

func mounts() []mountRow {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []mountRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		// id parent major:minor root mountpoint opts [optional…] - fstype source superopts
		fields := strings.Fields(sc.Text())
		sep := -1
		for i, x := range fields {
			if x == "-" {
				sep = i
				break
			}
		}
		if len(fields) < 5 || sep < 0 || sep+2 >= len(fields) {
			continue
		}
		out = append(out, mountRow{point: unescape(fields[4]), fstype: fields[sep+1], src: fields[sep+2]})
	}
	return out
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}

// FSOf says which filesystem path is on, and how full it is.
func FSOf(path string) (FS, bool) {
	var s unix.Statfs_t
	if unix.Statfs(path, &s) != nil {
		return FS{}, false
	}
	fs := FS{Total: int64(s.Blocks) * s.Bsize, Free: int64(s.Bfree) * s.Bsize,
		Avail: int64(s.Bavail) * s.Bsize}
	best := ""
	for _, m := range mounts() {
		if (path == m.point || strings.HasPrefix(path, strings.TrimSuffix(m.point, "/")+"/")) && len(m.point) >= len(best) {
			best, fs.Mount, fs.Type, fs.Device = m.point, m.point, m.fstype, m.src
		}
	}
	if fs.Mount == "" {
		fs.Mount = "/"
	}
	fs.RAM = s.Type == unix.TMPFS_MAGIC || s.Type == unix.RAMFS_MAGIC || fs.Type == "tmpfs" || fs.Type == "ramfs"
	return fs, true
}

// background lowers the calling OS thread's CPU and I/O priority: a scan
// must never be what slows an agent down. The caller holds the thread.
func background() {
	runtime.LockOSThread()
	tid := unix.Gettid()
	_ = unix.Setpriority(unix.PRIO_PROCESS, tid, 15)
	const whoProcess, classIdle = 1, 3
	_, _, _ = unix.Syscall(unix.SYS_IOPRIO_SET, whoProcess, uintptr(tid), classIdle<<13)
}
