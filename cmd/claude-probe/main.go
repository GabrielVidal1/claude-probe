// claude-probe: what every Bash call of Claude Code — and every process it
// started — really cost: CPU, peak memory, disk I/O, GPU and exit code, per
// call and per part of its command line, subagents included; plus the plan
// and the official usage reading at each turn.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/GabrielVidal1/claude-probe/internal/caps"
	"github.com/GabrielVidal1/claude-probe/internal/daemon"
	"github.com/GabrielVidal1/claude-probe/internal/hook"
	"github.com/GabrielVidal1/claude-probe/internal/paths"
	"github.com/GabrielVidal1/claude-probe/internal/probe"
	"github.com/GabrielVidal1/claude-probe/internal/report"
	"github.com/GabrielVidal1/claude-probe/internal/setup"
	"github.com/GabrielVidal1/claude-probe/internal/store"
)

var version = "dev"

const usage = `claude-probe — what each Bash call of Claude Code really cost.

  claude-probe install [--statusline] [--config-dir DIR]...   put the hooks in settings.json
  claude-probe uninstall [--config-dir DIR]...                take them out again
  sudo claude-probe setup-kernel [--remove]                    Linux: exact mode (eBPF), once
  claude-probe status                                          what runs, in which mode

  claude-probe report [SESSION] [--parts] [--json]   one session's calls (default: the latest)
  claude-probe top [--since 7d] [--by part|program|call] [--limit 20] [--json]
  claude-probe export [--after ID] [--limit N]       the raw records (JSON)

  claude-probe storage [--session ID] [--kind K] [--limit 20] [--json] [--scan]
                                    what sessions keep on disk: scratchpads, worktrees, transcripts
  claude-probe storage rm PATH… [--force] [--dry-run]       remove a scratch dir or a worktree, safely
  claude-probe storage clean [--scratch 3] [--worktrees 3] [--yes]
                                    the scratch dirs and merged worktrees quiet for N days (dry run
                                    without --yes)
  claude-probe storage config [--root DIR [--label L]] [--worktree-root DIR] [--rm-root DIR]
                              [--auto-clean DAYS]          extra dirs to track; the daemon's own cleaning

  claude-probe hook                 (Claude Code runs it)
  claude-probe statusline [--wrap CMD]   (the status line segment)
  claude-probe daemon [--idle 30m] [--no-kernel]   (started on demand by the hook)
  claude-probe debug                (run inside a Bash call: what the probe sees)
  claude-probe version
`

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd != "daemon" && cmd != "setup-kernel" {
		caps.Drop() // only the daemon needs the file capabilities (setup-kernel: root's own)
	}
	var err error
	switch cmd {
	case "hook":
		hook.Run(os.Stdin, os.Stdout, self())
	case "daemon":
		err = runDaemon(args)
	case "install":
		err = runInstall(args, false)
	case "uninstall":
		err = runInstall(args, true)
	case "setup-kernel":
		err = runSetupKernel(args)
	case "status":
		err = runStatus()
	case "report":
		err = runReport(args)
	case "top":
		err = runTop(args)
	case "storage":
		err = runStorage(args)
	case "statusline":
		fs := flag.NewFlagSet("statusline", flag.ExitOnError)
		wrap := fs.String("wrap", "", "the user's own status line command, run first")
		_ = fs.Parse(args)
		err = report.Statusline(os.Stdout, os.Stdin, paths.DB(), *wrap)
	case "export":
		fs := flag.NewFlagSet("export", flag.ExitOnError)
		after := fs.Int64("after", 0, "records after this id")
		limit := fs.Int("limit", 1000, "at most this many")
		_ = fs.Parse(args)
		var st *store.Store
		if st, err = store.Open(paths.DB(), true); err == nil {
			defer st.Close()
			err = report.Export(os.Stdout, st, *after, *limit)
		} else if os.IsNotExist(err) {
			fmt.Println(`{"records":[],"last":0,"head":0,"enabled":true}`)
			err = nil
		}
	case "debug":
		// what the probe sees from inside a Bash call: run it as one
		pid := os.Getppid()
		for i := 0; i < 8 && pid > 1; i++ {
			argv := probe.ArgvOf(pid)
			b, _ := json.Marshal(map[string]any{"pid": pid, "comm": probe.Comm(pid), "argv": argv,
				"toolCommand": probe.ToolCommand(argv), "uid": probe.UID(pid)})
			fmt.Println(string(b))
			pid = probe.ParentOf(pid)
		}
	case "version", "--version", "-v":
		b, _ := json.Marshal(map[string]string{"version": version})
		fmt.Println(string(b))
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "claude-probe:", err)
		os.Exit(1)
	}
}

func self() string {
	p, err := os.Executable()
	if err != nil {
		return "claude-probe"
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	idle := fs.Duration("idle", 30*time.Minute, "exit after this long with nothing to follow (0: never)")
	noKernel := fs.Bool("no-kernel", false, "sample /proc even when the kernel layer could load")
	noStorage := fs.Bool("no-storage", false, "don't track what sessions keep on disk")
	scanDelay := fs.Duration("scan-delay", time.Minute, "before the first storage pass")
	_ = fs.Parse(args)
	err := daemon.Run(daemon.Options{Idle: *idle, NoKernel: *noKernel, NoStorage: *noStorage,
		ScanDelay: *scanDelay, Version: version})
	if errors.Is(err, daemon.ErrRunning) {
		return nil
	}
	return err
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// hookBin is the binary the hooks should run: the capable copy setup-kernel
// installed, when there is one, else this one.
func hookBin() string {
	if setup.DefaultKernelPath != "" {
		if b, p := caps.FileCaps(setup.DefaultKernelPath); b && p {
			return setup.DefaultKernelPath
		}
	}
	return self()
}

func runInstall(args []string, remove bool) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	var dirs multi
	fs.Var(&dirs, "config-dir", "a Claude config dir (default: $CLAUDE_CONFIG_DIR or ~/.claude); repeatable")
	statusline := fs.Bool("statusline", false, "also show the last call's cost in the status line")
	bin := fs.String("bin", "", "the binary the hooks run (default: this one, or the setup-kernel copy)")
	_ = fs.Parse(args)
	b := *bin
	if b == "" {
		b = hookBin()
	}
	for _, p := range setup.SettingsPaths(dirs) {
		changed, err := setup.Apply(p, setup.Options{Bin: b, Statusline: *statusline, Remove: remove})
		if err != nil {
			return err
		}
		verb := map[bool]string{false: "hooks set in", true: "hooks removed from"}[remove]
		if !changed {
			verb = "already up to date:"
		}
		fmt.Printf("%s %s\n", verb, p)
	}
	if !remove {
		fmt.Println("New Claude Code sessions report from their first Bash call: `claude-probe report` to see them.")
		if runtime.GOOS == "linux" && b == self() {
			fmt.Println("Exact mode (every process, exit codes, from the kernel): sudo", self(), "setup-kernel")
		}
	}
	return nil
}

func runSetupKernel(args []string) error {
	fs := flag.NewFlagSet("setup-kernel", flag.ExitOnError)
	remove := fs.Bool("remove", false, "take the capabilities off again")
	target := fs.String("path", setup.DefaultKernelPath, "where the capable binary goes")
	_ = fs.Parse(args)
	if err := setup.SetupKernel(self(), *target, *remove); err != nil {
		return err
	}
	if *remove {
		fmt.Println("capabilities removed from", *target)
		return nil
	}
	fmt.Printf("%s: CAP_BPF + CAP_PERFMON set.\nNow, as yourself: %s install   (the hooks then run this copy)\n", *target, *target)
	return nil
}

func sockClient(timeout time.Duration) *http.Client {
	sock := paths.Socket()
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}}}
}

func health() (map[string]any, error) {
	c := sockClient(time.Second)
	resp, err := c.Get("http://probe/health")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var h map[string]any
	raw, _ := io.ReadAll(resp.Body)
	return h, json.Unmarshal(raw, &h)
}

func runStatus() error {
	fmt.Printf("claude-probe %s (%s/%s) at %s\n", version, runtime.GOOS, runtime.GOARCH, self())
	if runtime.GOOS == "linux" {
		b, p := caps.FileCaps(hookBin())
		mode := "sampled (/proc) — exact mode: sudo claude-probe setup-kernel"
		if b && p {
			mode = "exact (eBPF) available: " + hookBin() + " has CAP_BPF + CAP_PERFMON"
		}
		fmt.Println("kernel layer:", mode)
	} else {
		fmt.Println("kernel layer: kqueue (no setup)")
	}
	if h, err := health(); err == nil {
		fmt.Printf("daemon: running (pid %.0f), mode %v, %v call(s) in flight %v\n", h["pid"], h["mode"], h["running"], h["note"])
	} else {
		fmt.Println("daemon: not running (the next hook starts it)")
	}
	fmt.Println("store:", paths.DB())
	for _, p := range setup.SettingsPaths(nil) {
		raw, _ := os.ReadFile(p)
		fmt.Printf("hooks in %s: %v\n", p, strings.Contains(string(raw), setup.Marker))
	}
	return nil
}

func openStore() (*store.Store, error) {
	st, err := store.Open(paths.DB(), true)
	if os.IsNotExist(err) {
		return nil, errors.New("nothing recorded yet — `claude-probe install`, then run Claude Code")
	}
	return st, err
}

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	parts := fs.Bool("parts", false, "the parts of every call, not only the heavy ones")
	_ = fs.Parse(reorder(args))
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	return report.Report(os.Stdout, st, fs.Arg(0), *asJSON, *parts)
}

func runTop(args []string) error {
	fs := flag.NewFlagSet("top", flag.ExitOnError)
	since := fs.String("since", "7d", "how far back (e.g. 24h, 7d, 30d)")
	by := fs.String("by", "part", "part | program | call")
	limit := fs.Int("limit", 20, "rows")
	asJSON := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	d, err := parseSince(*since)
	if err != nil {
		return err
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	return report.Top(os.Stdout, st, d, *by, *limit, *asJSON)
}

func parseSince(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		var n int
		if _, err := fmt.Sscanf(s, "%dd", &n); err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// reorder puts flags before positionals (`report SID --json` works).
func reorder(args []string) []string {
	var flags, pos []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		} else {
			pos = append(pos, a)
		}
	}
	return append(flags, pos...)
}
