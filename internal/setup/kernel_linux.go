//go:build linux

package setup

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// DefaultKernelPath is where `setup-kernel` installs the capable binary: a
// root-owned file in a root-owned directory, so no user can swap it.
const DefaultKernelPath = "/usr/local/bin/claude-probe"

// SetupKernel (as root) copies the binary to target, makes it root-owned and
// gives it CAP_BPF + CAP_PERFMON as file capabilities — what the daemon
// needs to load its kernel program as the normal user. It only ever loads
// its own embedded program, follows only the calling user's agents, and
// drops the capabilities right after loading. remove takes them off again.
func SetupKernel(self, target string, remove bool) error {
	if os.Geteuid() != 0 {
		return errors.New("needs root: sudo claude-probe setup-kernel")
	}
	if remove {
		if err := unix.Removexattr(target, "security.capability"); err != nil && !errors.Is(err, unix.ENODATA) {
			return err
		}
		return nil
	}
	if self != target {
		if err := copyFile(self, target); err != nil {
			return err
		}
	}
	if err := os.Chown(target, 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(target, 0o755); err != nil {
		return err
	}
	return unix.Setxattr(target, "security.capability", capData(), 0)
}

// capData is a vfs_cap_data v2: CAP_BPF and CAP_PERFMON permitted and
// effective (+ CAP_SYS_RESOURCE on kernels before 5.11, where BPF memory is
// charged to RLIMIT_MEMLOCK).
func capData() []byte {
	var lo, hi uint32
	hi |= 1<<(unix.CAP_BPF-32) | 1<<(unix.CAP_PERFMON-32)
	if kernelBefore(5, 11) {
		lo |= 1 << unix.CAP_SYS_RESOURCE
	}
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b[0:], 0x02000000|0x1) // VFS_CAP_REVISION_2 | EFFECTIVE
	binary.LittleEndian.PutUint32(b[4:], lo)
	binary.LittleEndian.PutUint32(b[12:], hi)
	return b
}

func kernelBefore(major, minor int) bool {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return false
	}
	rel := unix.ByteSliceToString(u.Release[:])
	parts := strings.SplitN(rel, ".", 3)
	if len(parts) < 2 {
		return false
	}
	ma, _ := strconv.Atoi(parts[0])
	mi, _ := strconv.Atoi(strings.TrimFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }))
	return ma < major || (ma == major && mi < minor)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("%s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
