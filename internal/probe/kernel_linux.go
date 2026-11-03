//go:build linux

package probe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// The kernel layer: the CO-RE program in bpf/probe.bpf.c, loaded and
// attached by the daemon itself. Needs CAP_BPF + CAP_PERFMON (the
// `setup-kernel` file capabilities, or root) and a kernel with BTF (≥ 5.8).

const (
	evFork = 1
	evExec = 2
	evExit = 3
	argvLen = 2048
)

type evSmall struct {
	Type, Pid, Ppid uint32
	Code            int32
	Ts, Start       uint64
	CPU, CCPU       uint64
	MaxRss          uint64
	Rchar, Wchar    uint64
	Rbytes, Wbytes  uint64
	Comm            [16]byte
}

type evExecRec struct {
	Type, Pid, Ppid, Root uint32
	Ts, Start             uint64
	ArgvLen, Pad          uint32
	Comm                  [16]byte
	Argv                  [argvLen]byte
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// Kernel is a running kernel layer.
type Kernel struct {
	objs  probeObjects
	links []link.Link
	rd    *ringbuf.Reader
	feed  *Feed
	uid   uint32
	stop  chan struct{}
	once  sync.Once
	Notes []string
}

// StartKernel loads the program for `uid`'s agents and starts feeding.
func StartKernel(feed *Feed, uid uint32) (*Kernel, error) {
	_ = rlimit.RemoveMemlock() // kernels < 5.11 account BPF memory to RLIMIT_MEMLOCK
	spec, err := loadProbe()
	if err != nil {
		return nil, err
	}
	// cilium/ebpf would read the kernel version from the vDSO through
	// /proc/self/mem, which a binary running on file capabilities may not
	// open (it isn't dumpable — and must stay so): uname says it too.
	if kv := unameVersion(); kv != 0 {
		for _, p := range spec.Programs {
			if p.Type == ebpf.Kprobe {
				p.KernelVersion = kv
			}
		}
	}
	if v, ok := spec.Variables["target_uid"]; ok {
		if err := v.Set(uid); err != nil {
			return nil, err
		}
	}
	k := &Kernel{feed: feed, uid: uid, stop: make(chan struct{})}
	if err := spec.LoadAndAssign(&k.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier: %v", strings.Join(ve.Log[max(0, len(ve.Log)-5):], " | "))
		}
		return nil, err
	}
	for _, p := range []*ebpf.Program{k.objs.OnNewtask, k.objs.OnExec, k.objs.OnExit} {
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			k.Close()
			return nil, fmt.Errorf("attach %s: %w", p, err)
		}
		k.links = append(k.links, l)
	}
	// the image's own peak RSS; without it, the kernel's maxrss (which counts
	// what a fork inherited before exec)
	if l, err := link.AttachTracing(link.TracingOptions{Program: k.objs.OnAcctCollect}); err == nil {
		k.links = append(k.links, l)
	} else {
		k.Notes = append(k.Notes, "no acct_collect fentry ("+err.Error()+"): peak RSS includes pre-exec memory")
	}
	if k.rd, err = ringbuf.NewReader(k.objs.Events); err != nil {
		k.Close()
		return nil, err
	}
	since := nowF()
	k.seed()
	feed.Beat(since, 0)
	feed.OnRoot = func(pid int) { _ = k.objs.Tracked.Update(uint32(pid), uint8(2), ebpf.UpdateAny) }
	go k.read()
	go k.beat(since)
	return k, nil
}

func (k *Kernel) Close() {
	k.once.Do(func() {
		close(k.stop)
		if k.rd != nil {
			k.rd.Close()
		}
		for _, l := range k.links {
			l.Close()
		}
		k.objs.Close()
		k.feed.Stop()
	})
}

// seed tracks the agents already running, and everything under them.
func (k *Kernel) seed() {
	parent := ProcList()
	kids := map[int][]int{}
	for p, pp := range parent {
		kids[pp] = append(kids[pp], p)
	}
	type item struct {
		pid  int
		root bool
	}
	var stack []item
	for p := range parent {
		if Comm(p) == "claude" && UID(p) == int(k.uid) {
			stack = append(stack, item{p, true})
		}
	}
	seen := map[int]bool{}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[it.pid] {
			continue
		}
		seen[it.pid] = true
		val := uint8(1)
		if it.root {
			val = 2
		}
		_ = k.objs.Tracked.Update(uint32(it.pid), val, ebpf.UpdateAny)
		if st := readStat(it.pid); st != nil {
			k.feed.Exec(it.pid, parent[it.pid], st.Started, st.Comm, argvOf(it.pid))
		}
		for _, c := range kids[it.pid] {
			stack = append(stack, item{c, false})
		}
	}
}

func (k *Kernel) beat(since float64) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-k.stop:
			return
		case <-t.C:
			var lost uint64
			_ = k.objs.Lost.Lookup(uint32(0), &lost)
			k.feed.Beat(since, lost)
			if n++; n%4 == 0 {
				k.seed() // agents whose exec predates us, a missed event
			}
		}
	}
}

func (k *Kernel) read() {
	for {
		rec, err := k.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		raw := rec.RawSample
		if len(raw) < 4 {
			continue
		}
		switch binary.LittleEndian.Uint32(raw) {
		case evFork:
			var e evSmall
			if binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e) == nil {
				k.feed.Fork(int(e.Pid), int(e.Ppid), BootNsToEpoch(e.Ts), cstr(e.Comm[:]))
			}
		case evExec:
			var e evExecRec
			if binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e) == nil {
				n := min(int(e.ArgvLen), argvLen)
				var argv []string
				for _, a := range bytes.Split(e.Argv[:n], []byte{0}) {
					if len(a) > 0 {
						argv = append(argv, string(a))
					}
				}
				k.feed.Exec(int(e.Pid), int(e.Ppid), BootNsToEpoch(e.Start), cstr(e.Comm[:]), argv)
			}
		case evExit:
			var e evSmall
			if binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e) == nil {
				x := &Exit{T: BootNsToEpoch(e.Ts), Start: BootNsToEpoch(e.Start), Ppid: int(e.Ppid),
					CPU: float64(e.CPU) / 1e9, CPUChildren: float64(e.CCPU) / 1e9,
					MaxRss: int64(e.MaxRss) * pageSize,
					IO: map[string]int64{"rchar": int64(e.Rchar), "wchar": int64(e.Wchar),
						"read_bytes": int64(e.Rbytes), "write_bytes": int64(e.Wbytes)}}
				if c := int(e.Code); c&0x7f != 0 {
					s := c & 0x7f
					x.Signal = &s
				} else {
					v := (c >> 8) & 0xff
					x.Code = &v
				}
				k.feed.ExitEv(int(e.Pid), x)
			}
		}
	}
}

// unameVersion is KERNEL_VERSION(a, b, c) of the running kernel.
func unameVersion() uint32 {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return 0
	}
	var a, b, c uint32
	fmt.Sscanf(unix.ByteSliceToString(u.Release[:]), "%d.%d.%d", &a, &b, &c)
	return a<<16 | b<<8 | min(c, 255)
}
