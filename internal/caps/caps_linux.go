//go:build linux

// Package caps drops the file capabilities `setup-kernel` gives the binary
// once they are no longer needed — every command but the daemon drops them
// at start, the daemon right after it has loaded the kernel program.
package caps

import (
	"encoding/binary"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Drop clears every capability of every thread (capset is per thread; Go
// runs many). Needs a cgo-free build (AllThreadsSyscall).
func Drop() {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	_, _, _ = syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])), 0)
}

// Effective reports whether the process holds CAP_BPF and CAP_PERFMON (or is root).
func Effective() bool {
	if unix.Geteuid() == 0 {
		return true
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if unix.Capget(&hdr, &data[0]) != nil {
		return false
	}
	const want = 1<<(unix.CAP_BPF-32) | 1<<(unix.CAP_PERFMON-32)
	return data[1].Effective&want == want
}

// FileCaps reads the binary's `security.capability` xattr: which of
// CAP_BPF / CAP_PERFMON it grants.
func FileCaps(path string) (bpf, perfmon bool) {
	buf := make([]byte, 24)
	n, err := unix.Getxattr(path, "security.capability", buf)
	if err != nil || n < 20 {
		return false, false
	}
	hi := binary.LittleEndian.Uint32(buf[12:16])
	return hi&(1<<(unix.CAP_BPF-32)) != 0, hi&(1<<(unix.CAP_PERFMON-32)) != 0
}
