// SPDX-License-Identifier: GPL-2.0
// The call probe's kernel side, CO-RE: compiled once, loaded on any kernel
// with BTF (>= 5.8 for the ring buffer). Tracks the processes under every
// agent root (a `claude` process of the probe's user) from fork to exit and
// reports each exit's exact cost.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define ARGV_LEN 2048
#define CLONE_THREAD 0x00010000
#define SIGNAL_GROUP_EXIT 0x00000004

enum { EV_FORK = 1, EV_EXEC = 2, EV_EXIT = 3 };

struct ev_small {
	__u32 type, pid, ppid;
	__s32 code;
	__u64 ts, start, cpu, ccpu, maxrss;
	__u64 rchar, wchar, rbytes, wbytes;
	char comm[16];
};

struct ev_exec {
	__u32 type, pid, ppid, root;
	__u64 ts, start;
	__u32 argv_len, _pad;
	char comm[16];
	char argv[ARGV_LEN];
};

// set by the loader: the uid whose agents are traced, the root programs' names
const volatile __u32 target_uid = 0;
const volatile char root_comm[16] = "claude";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 131072);
	__type(key, __u32);
	__type(value, __u8);
} tracked SEC(".maps");   // tgid -> 1 descendant, 2 root (userspace may add roots)

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 131072);
	__type(key, __u32);
	__type(value, __u64);
} peak SEC(".maps");      // tgid -> its image's high-water RSS (pages)

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lost SEC(".maps");

static __always_inline void count_lost(void)
{
	__u32 k = 0;
	__u64 *v = bpf_map_lookup_elem(&lost, &k);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline int is_root(const char *c)
{
#pragma unroll
	for (int i = 0; i < 16; i++) {
		if (c[i] != root_comm[i])
			return 0;
		if (c[i] == 0)
			return 1;
	}
	return 1;
}

// mm->rss_stat: an array of percpu counters since 6.2, an atomic array before
struct mm_rss_stat___old {
	atomic_long_t count[4];
} __attribute__((preserve_access_index));
struct mm_struct___old {
	struct mm_rss_stat___old rss_stat;
} __attribute__((preserve_access_index));

static __always_inline __s64 mm_rss(struct mm_struct *mm)
{
	if (bpf_core_type_exists(struct mm_rss_stat___old)) {
		struct mm_struct___old *o = (void *)mm;
		return BPF_CORE_READ(o, rss_stat.count[0].counter) +
		       BPF_CORE_READ(o, rss_stat.count[1].counter) +
		       BPF_CORE_READ(o, rss_stat.count[3].counter);
	}
	return BPF_CORE_READ(mm, rss_stat[0].count) + BPF_CORE_READ(mm, rss_stat[1].count) +
	       BPF_CORE_READ(mm, rss_stat[3].count);   // file, anon, shmem pages
}

static __always_inline __u32 cur_uid(void)
{
	return (__u32)bpf_get_current_uid_gid();
}

SEC("tp_btf/task_newtask")
int BPF_PROG(on_newtask, struct task_struct *task, __u64 clone_flags)
{
	if (clone_flags & CLONE_THREAD)
		return 0;
	__u32 parent = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &parent))
		return 0;
	__u32 child = BPF_CORE_READ(task, pid);
	__u8 one = 1;
	bpf_map_update_elem(&tracked, &child, &one, BPF_ANY);
	struct ev_small *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_lost();
		return 0;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->type = EV_FORK;
	e->pid = child;
	e->ppid = parent;
	e->ts = bpf_ktime_get_boot_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));
	__u8 *t = bpf_map_lookup_elem(&tracked, &tgid);
	int root = !t && cur_uid() == target_uid && is_root(comm);
	if (!t && !root)
		return 0;
	if (root) {
		__u8 two = 2;
		bpf_map_update_elem(&tracked, &tgid, &two, BPF_ANY);
	}
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct ev_exec *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_lost();
		return 0;
	}
	e->type = EV_EXEC;
	e->pid = tgid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->root = root;
	e->ts = bpf_ktime_get_boot_ns();
	e->start = BPF_CORE_READ(task, group_leader, start_boottime);
	__builtin_memcpy(&e->comm, comm, sizeof(comm));
	unsigned long as = BPF_CORE_READ(task, mm, arg_start);
	unsigned long ae = BPF_CORE_READ(task, mm, arg_end);
	__u64 len = ae > as ? ae - as : 0;
	if (len > ARGV_LEN - 1)
		len = ARGV_LEN - 1;
	len &= (ARGV_LEN - 1);
	e->argv_len = 0;
	if (len > 0 && bpf_probe_read_user(&e->argv, len, (void *)as) == 0)
		e->argv_len = len;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// do_exit() calls acct_collect() before exit_mm(): the last moment the
// process's own image can be read (signal->maxrss would also hold what a fork
// inherited before exec).
// fentry, not a kprobe: a kprobe goes through perf_event_open, which
// Debian's perf_event_paranoid=3 refuses to anything short of CAP_SYS_ADMIN;
// a BPF trampoline needs only CAP_BPF + CAP_PERFMON (arm64: kernel >= 6.0).
SEC("fentry/acct_collect")
int BPF_PROG(on_acct_collect, long exitcode, int group_dead)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return 0;
	__u64 hw = BPF_CORE_READ(mm, hiwater_rss);
	__s64 rss = mm_rss(mm);
	if (rss > 0 && (__u64)rss > hw)
		hw = rss;
	__u64 *cur = bpf_map_lookup_elem(&peak, &tgid);
	if (!cur || *cur < hw)
		bpf_map_update_elem(&peak, &tgid, &hw, BPF_ANY);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct signal_struct *sig = BPF_CORE_READ(task, signal);
	if (BPF_CORE_READ(sig, live.counter) != 0)
		return 0;   // another thread of the process still runs
	struct ev_small *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_lost();
		bpf_map_delete_elem(&tracked, &tgid);
		bpf_map_delete_elem(&peak, &tgid);
		return 0;
	}
	e->type = EV_EXIT;
	e->pid = tgid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->ts = bpf_ktime_get_boot_ns();
	e->start = BPF_CORE_READ(task, group_leader, start_boottime);
	int code = BPF_CORE_READ(task, exit_code);
	if (BPF_CORE_READ(sig, flags) & SIGNAL_GROUP_EXIT)
		code = BPF_CORE_READ(sig, group_exit_code);
	e->code = code;
	e->cpu = BPF_CORE_READ(sig, sum_sched_runtime) + BPF_CORE_READ(task, se.sum_exec_runtime);
	e->ccpu = BPF_CORE_READ(sig, cutime) + BPF_CORE_READ(sig, cstime);
	__u64 *pk = bpf_map_lookup_elem(&peak, &tgid);
	e->maxrss = pk ? *pk : BPF_CORE_READ(sig, maxrss);
	e->rchar = e->wchar = e->rbytes = e->wbytes = 0;
	if (bpf_core_field_exists(task->ioac)) {   // CONFIG_TASK_XACCT / _IO_ACCOUNTING
		e->rchar = BPF_CORE_READ(sig, ioac.rchar) + BPF_CORE_READ(task, ioac.rchar);
		e->wchar = BPF_CORE_READ(sig, ioac.wchar) + BPF_CORE_READ(task, ioac.wchar);
		e->rbytes = BPF_CORE_READ(sig, ioac.read_bytes) + BPF_CORE_READ(task, ioac.read_bytes);
		e->wbytes = BPF_CORE_READ(sig, ioac.write_bytes) + BPF_CORE_READ(task, ioac.write_bytes);
	}
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&tracked, &tgid);
	bpf_map_delete_elem(&peak, &tgid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
