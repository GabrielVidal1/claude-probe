package storage

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// FS is the filesystem a path lives on.
type FS struct {
	Mount  string `json:"mount"`
	Type   string `json:"fsType"`
	RAM    bool   `json:"ram,omitempty"`
	Total  int64  `json:"total"`
	Free   int64  `json:"free"`
	Avail  int64  `json:"avail"`
	Device string `json:"device,omitempty"`
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// FSOf says which filesystem path is on, and how full it is.
func FSOf(path string) (FS, bool) {
	var s unix.Statfs_t
	if unix.Statfs(path, &s) != nil {
		return FS{}, false
	}
	bs := int64(s.Bsize)
	fs := FS{Mount: cstr(s.Mntonname[:]), Type: cstr(s.Fstypename[:]), Device: cstr(s.Mntfromname[:]),
		Total: int64(s.Blocks) * bs, Free: int64(s.Bfree) * bs, Avail: int64(s.Bavail) * bs}
	return fs, true
}

// background lowers the calling thread's priority (macOS: the background
// QoS band also throttles its disk I/O).
func background() {
	runtime.LockOSThread()
	_ = unix.Setpriority(unix.PRIO_DARWIN_THREAD, 0, unix.PRIO_DARWIN_BG)
}
