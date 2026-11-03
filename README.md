# claude-probe

What every Bash call of [Claude Code](https://claude.com/claude-code) really
cost — and every process it started: CPU, peak memory, disk I/O, GPU and exit
code, per call and per part of its command line (`cd x && npm run build | tail`
is three parts), subagents included. Plus, at each turn, the account's plan and
its official usage reading. Claude Code's transcript keeps none of this.

One static binary for Linux and macOS. No Docker, no Python, no daemon to
install: the hook starts it when the first call comes.

```sh
curl -fsSL https://raw.githubusercontent.com/GabrielVidal1/claude-probe/main/install.sh | sh
```

That puts `claude-probe` in `~/.local/bin` and its hooks in
`~/.claude/settings.json` (yours are kept). New Claude Code sessions report from
their first Bash call.

```text
$ claude-probe report
session 5a405517-… · 5 calls · 0.91 s CPU · peak 132 MB · 5/5 from the kernel

      TIME    WALL     CPU     PEAK  EXIT COMMAND
  23:17:51  671 ms  0.62 s   132 MB     0 python3 -c 'x=bytearray(120*1024*1024) …
            612 ms  0.61 s   129 MB     0   └ python3
  23:17:53   52 ms   20 ms   9.2 MB     0 ls /nonexistent; echo after
             32 ms   14 ms   6.1 MB     2   └ ls
  23:18:01   69 ms  0.22 s   20.4 MB    0 [general-purpose] find /usr/lib -name "*.so" | wc -l

$ claude-probe top --since 7d
     CPU  RUNS     MAX    PEAK  AVG WALL  SESSIONS  PART
  51 s       1    51 s  918 MB     49 s         1  tsc
  21 s       1    21 s  1.0 GB     18 s         1  npm run build
```

## How exact

| | Linux | macOS |
|---|---|---|
| Every process, even 1-ms ones | ✅ kernel (eBPF) | ✅ kqueue |
| Exit codes, nested too | ✅ | ✅ |
| CPU per process | ✅ | ✅ |
| Peak memory, disk I/O | ✅ | ✅ (a lower bound when the parent reaps first) |
| Setup | `sudo claude-probe setup-kernel`, once | none |

- **Linux, exact mode**: a CO-RE eBPF program embedded in the binary follows
  every fork, exec and exit under your `claude` processes. Loading it needs
  `CAP_BPF` + `CAP_PERFMON`: `sudo claude-probe setup-kernel` copies the
  binary to `/usr/local/bin` (root-owned) and gives it those two file
  capabilities — it loads only its own program, traces only your own agents,
  and drops them right after loading. Kernel ≥ 5.8 with BTF (every current
  distribution). Without it, the probe samples `/proc` (processes shorter
  than a sample fold into their parent; no exit codes for nested ones).
- **macOS, no setup**: kqueue (`EVFILT_PROC`) reports fork, exec and exit with
  the exit status for any process of yours, and `proc_pid_rusage` still
  answers for a process that just exited — exact CPU, lifetime peak footprint
  and disk I/O, unless its parent reaps it first (then the last 40-ms sample
  stands, flagged `exact: false`; the call's CPU still counts it through the
  shell's own child time).

## How it attributes

Claude Code hands every hook the call's `tool_use_id`, the turn's `prompt_id`
and, inside a subagent, its `agent_id`. The hook (`claude-probe hook`, prints
nothing, never blocks a call) passes them to the daemon before the call's shell
starts; the daemon takes the session's new `bash -c "… eval '<cmd>' …"` child
whose command matches, then follows everything under it — background jobs and
`setsid` daemons until they exit (24 h at most).

## Commands

```text
claude-probe install [--statusline] [--config-dir DIR]…   the hooks (and the status-line segment)
claude-probe uninstall [--config-dir DIR]…
sudo claude-probe setup-kernel [--remove]                  Linux exact mode, once
claude-probe status

claude-probe report [SESSION] [--parts] [--json]            one session (default: the latest)
claude-probe top [--since 7d] [--by part|program|call]      the heaviest commands
claude-probe export [--after ID]                            the raw records (JSON)
```

`--statusline` wraps your own status line and appends the session's last call
and the week's usage: `… │ ⚙ npm run build 9.9 s · 900 MB · wk 27%`.

Data stays on the machine: `~/.local/state/claude-probe/probe.db` (macOS:
`~/Library/Application Support/claude-probe/`), 30 days.

## Building

```sh
make build          # bin/claude-probe (Go only: the eBPF objects are committed)
make test
make generate       # recompile internal/probe/bpf/probe.bpf.c (needs Docker: clang + bpftool)
make dist           # release binaries + checksums.txt
```

MIT.
