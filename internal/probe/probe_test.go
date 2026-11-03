package probe

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/GabrielVidal1/claude-probe/internal/store"
)

func TestNormCommandDropsRtk(t *testing.T) {
	for in, want := range map[string]string{"rtk ls  /tmp | rtk proxy grep x": "ls /tmp | grep x",
		"cd a && rtk git status": "cd a && git status", "echo rtk": "echo rtk"} {
		if got := NormCommand(in); got != want {
			t.Fatalf("%q → %q", in, got)
		}
	}
}

func TestToolCommandAndLabels(t *testing.T) {
	argv := []string{"/bin/bash", "-c", "source /x/snap.sh && eval 'npm run build 2>&1 | tail' < /dev/null && pwd -P >| /tmp/cwd"}
	if got := ToolCommand(argv); got != "npm run build 2>&1 | tail" {
		t.Fatal(got)
	}
	if got := ToolCommand([]string{"/bin/bash", "-c", "eval 'echo very long and cut"}); got != "echo very long and cut" {
		t.Fatal(got)
	}
	// Claude Code writes a quote inside the eval as '"'"'
	cc := []string{"/bin/bash", "-c", `source s && eval 'python3 - <<'"'"'EOF'"'"'` + "\nprint(1)\nEOF' < /dev/null && pwd -P >| /tmp/x"}
	if got := ToolCommand(cc); got != "python3 - <<'EOF'\nprint(1)\nEOF" {
		t.Fatalf("%q", got)
	}
	if got := CommandLabel("cd x && npm run build 2>&1 | tail"); got != "npm run build" {
		t.Fatal(got)
	}
	if got := Label([]string{"/usr/bin/python3.13", "-m", "http.server"}, "python3"); got != "python3 -m http.server" {
		t.Fatal(got)
	}
	if got := Label([]string{"timeout", "30", "pytest", "-q"}, "timeout"); got != "pytest" {
		t.Fatal(got)
	}
}

func ip(v int) *int { return &v }

func newProbe(t *testing.T, feed *Feed) (*Probe, *store.Store) {
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, feed), st
}

func lastCall(t *testing.T, st *store.Store, tid string) map[string]any {
	r := st.Newest("call", tid)
	if r == nil {
		t.Fatal("no record for", tid)
	}
	var d map[string]any
	_ = json.Unmarshal(r.Data, &d)
	return d
}

// A call seen whole by the kernel layer: exact totals, exit codes, a
// re-parented daemon, I/O of a reaped child counted once.
func TestKernelRecordIsExact(t *testing.T) {
	now := nowF()
	feed := NewFeed()
	feed.Beat(now-100, 0)
	const root = 424242 // not a live pid: the probe only reads the feed
	shell := []string{"/bin/bash", "-c", "eval 'ls /nope; echo after' < /dev/null"}
	feed.Fork(100, root, now+0.01, "claude")
	feed.Exec(100, root, now+0.01, "bash", shell)
	feed.Fork(101, 100, now+0.02, "bash")
	feed.Exec(101, 100, now+0.02, "ls", []string{"ls", "/nope"})
	feed.ExitEv(101, &Exit{T: now + 0.03, Start: now + 0.02, Ppid: 100, Code: ip(2), CPU: 0.002,
		MaxRss: 2 << 20, IO: map[string]int64{"rchar": 100}})
	feed.Fork(102, 100, now+0.04, "bash")
	feed.ExitEv(102, &Exit{T: now + 0.5, Start: now + 0.04, Ppid: 1, Signal: ip(15), CPU: 0.001,
		MaxRss: 1 << 20, IO: map[string]int64{"rchar": 10}})
	feed.ExitEv(100, &Exit{T: now + 0.06, Start: now + 0.01, Ppid: root, Code: ip(0), CPU: 0.008,
		CPUChildren: 0.002, MaxRss: 3 << 20, IO: map[string]int64{"rchar": 400}})

	pr, st := newProbe(t, feed)
	pr.Handle(Event{E: "pre", Tid: "toolu_A", Sid: "S", AgentID: "ag", AgentType: "Explore",
		Command: "ls /nope; echo after", T: now, Chain: []int{root}})
	pr.calls["toolu_A"].root = root
	dm := int64(60)
	pr.Handle(Event{E: "post", Tid: "toolu_A", DurationMs: &dm, Command: "rtk ls /nope; echo after", T: now + 0.07})
	for i := 0; i < 5 && pr.Running() > 0; i++ {
		pr.Tick()
	}
	d := lastCall(t, st, "toolu_A")
	if d["source"] != "kernel" || d["status"] != "done" || d["exitCode"] != 0.0 || d["agentType"] != "Explore" || d["rewritten"] != true {
		t.Fatal(d)
	}
	procs := d["procs"].([]any)
	if len(procs) != 3 {
		t.Fatal(procs)
	}
	by := map[float64]map[string]any{}
	for _, p := range procs {
		m := p.(map[string]any)
		by[m["pid"].(float64)] = m
	}
	if by[101]["exitCode"] != 2.0 || by[101]["peakRss"] != float64(2<<20) || by[102]["signal"] != 15.0 {
		t.Fatal(by)
	}
	tot := d["totals"].(map[string]any)
	if math.Abs(tot["cpu"].(float64)-0.011) > 1e-6 {
		t.Fatal(tot)
	}
	// the shell's counters include the child it reaped — counted once
	if io := tot["io"].(map[string]any); io["rchar"] != float64(400-100+100+10) {
		t.Fatal(io)
	}
}

func TestParallelCallsGetTheirOwnShells(t *testing.T) {
	now := nowF()
	feed := NewFeed()
	feed.Beat(now-9, 0)
	const root = 424243
	for _, x := range []struct {
		pid int
		cmd string
		dt  float64
	}{{200, "rtk git status", 0.02}, {201, "echo b", 0.01}} {
		feed.Fork(x.pid, root, now+x.dt, "claude")
		feed.Exec(x.pid, root, now+x.dt, "bash", []string{"/bin/bash", "-c", "eval '" + x.cmd + "' < /dev/null"})
		feed.ExitEv(x.pid, &Exit{T: now + x.dt + 0.1, Start: now + x.dt, Ppid: root, Code: ip(0), CPU: 0.01})
	}
	pr, st := newProbe(t, feed)
	for _, c := range []struct{ tid, cmd string }{{"toolu_1", "git status"}, {"toolu_2", "echo b"}} {
		pr.Handle(Event{E: "pre", Tid: c.tid, Sid: "S", Command: c.cmd, T: now, Chain: []int{root}})
		pr.calls[c.tid].root = root
		pr.Handle(Event{E: "post", Tid: c.tid, T: now + 0.2})
	}
	for i := 0; i < 5 && pr.Running() > 0; i++ {
		pr.Tick()
	}
	for tid, pid := range map[string]float64{"toolu_1": 200, "toolu_2": 201} {
		p := lastCall(t, st, tid)["procs"].([]any)[0].(map[string]any)
		if p["pid"] != pid {
			t.Fatal(tid, p)
		}
	}
}

func TestMarkCarriesPlan(t *testing.T) {
	dir := t.TempDir()
	_ = writeJSON(filepath.Join(dir, ".claude.json"), map[string]any{"oauthAccount": map[string]any{
		"planDisplayName": "Max", "emailAddress": "never@copied", "accountUuid": "u1"}})
	pr, st := newProbe(t, nil)
	pr.Handle(Event{E: "prompt", Sid: "S", PromptID: "p1", ConfigDir: dir, T: 100})
	recs, _ := st.Latest("mark", "S", 0)
	if len(recs) != 1 {
		t.Fatal(recs)
	}
	var d map[string]any
	_ = json.Unmarshal(recs[0].Data, &d)
	pl := d["plan"].(map[string]any)
	if pl["planDisplayName"] != "Max" || pl["emailAddress"] != nil {
		t.Fatal(pl)
	}
}

func writeJSON(path string, v any) error {
	raw, _ := json.Marshal(v)
	return os.WriteFile(path, raw, 0o600)
}

// macOS: an exit read too late (approximate) is still an exit — the call
// stays kernel-sourced; a process that exec'd in place is renamed.
func TestApproxExitsAndExecInPlace(t *testing.T) {
	now := nowF()
	feed := NewFeed()
	feed.Beat(now-100, 0)
	const root = 424244
	feed.Fork(300, root, now+0.01, "claude")
	feed.Exec(300, root, now+0.01, "zsh", []string{"/bin/zsh", "-c", "eval '(sleep 0; perl -e 1) & wait' < /dev/null"})
	feed.Fork(301, 300, now+0.02, "zsh")
	feed.Exec(301, 300, now+0.02, "zsh", []string{"/bin/zsh", "-c", "eval 'x' < /dev/null"})
	feed.Exec(301, 300, now+0.02, "perl", []string{"perl", "-e", "1"}) // exec in place
	feed.ExitEv(301, &Exit{T: now + 0.05, Start: now + 0.02, Ppid: 300, Code: ip(0), Approx: true})
	feed.ExitEv(300, &Exit{T: now + 0.06, Start: now + 0.01, Ppid: root, Code: ip(0), CPU: 0.01})
	pr, st := newProbe(t, feed)
	pr.Handle(Event{E: "pre", Tid: "toolu_M", Sid: "S", Command: "(sleep 0; perl -e 1) & wait", T: now, Chain: []int{root}})
	pr.calls["toolu_M"].root = root
	pr.Handle(Event{E: "post", Tid: "toolu_M", T: now + 0.1})
	for i := 0; i < 5 && pr.Running() > 0; i++ {
		pr.Tick()
	}
	d := lastCall(t, st, "toolu_M")
	if d["source"] != "kernel" {
		t.Fatal("an approximate exit downgraded the call:", d["source"])
	}
	var perl map[string]any
	for _, p := range d["procs"].([]any) {
		if m := p.(map[string]any); m["pid"] == 301.0 {
			perl = m
		}
	}
	if perl["label"] != "perl -e" || perl["exact"] != false {
		t.Fatal(perl)
	}
}
