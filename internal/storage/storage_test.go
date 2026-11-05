package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GabrielVidal1/claude-probe/internal/store"
)

func write(t *testing.T, p string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, make([]byte, n), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWalkOwnVsShared(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "item")
	write(t, filepath.Join(root, "scratchpad", "dl", "big"), 1<<20)
	write(t, filepath.Join(root, "scratchpad", "a"), 64<<10)
	// two links, both inside: owned, counted once
	if err := os.Link(filepath.Join(root, "scratchpad", "a"), filepath.Join(root, "tasks-a")); err != nil {
		t.Fatal(err)
	}
	// a link to a file outside: on disk here, but not owned
	write(t, filepath.Join(d, "outside"), 256<<10)
	if err := os.Link(filepath.Join(d, "outside"), filepath.Join(root, "scratchpad", "dl", "shared")); err != nil {
		t.Fatal(err)
	}
	tl := Walk(root, true, "scratchpad")
	if tl.Own >= tl.Bytes {
		t.Fatalf("own %d should be below bytes %d (a shared file)", tl.Own, tl.Bytes)
	}
	if d := tl.Bytes - tl.Own; d < 200<<10 || d > 300<<10 {
		t.Fatalf("shared part = %d, want ~256K", d)
	}
	names := map[string]Entry{}
	for _, e := range tl.Children {
		names[e.Name] = e
	}
	if _, ok := names["scratchpad/dl"]; !ok {
		t.Fatalf("children %v: want scratchpad/dl listed", tl.Children)
	}
	if _, ok := names["tasks-a"]; !ok {
		t.Fatalf("children %v: want tasks-a listed", tl.Children)
	}
	if tl.Children[0].Name != "scratchpad/dl" {
		t.Fatalf("biggest first: %v", tl.Children)
	}
}

func TestWorktreeOp(t *testing.T) {
	cases := []struct {
		argv, cwd, op, path string
	}{
		{"git worktree add /w/x -b x", "/r", "add", "/w/x"},
		{"git -C /home/u/homelab worktree add -b feat /home/u/worktrees/homelab-feat", "", "add", "/home/u/worktrees/homelab-feat"},
		{"git worktree add ../wt main", "/repo/sub", "add", "/repo/wt"},
		{"git worktree add -B br --lock --reason why /abs/p", "", "add", "/abs/p"},
		{"/usr/bin/git worktree remove --force /w/x", "", "remove", "/w/x"},
		{"git worktree list", "/r", "", ""},
		{"git status", "/r", "", ""},
		{"npm worktree add /x", "/r", "", ""},
	}
	for _, c := range cases {
		op, p := WorktreeOp(strings.Fields(c.argv), c.cwd)
		if op != c.op || p != c.path {
			t.Errorf("%q: got (%q, %q), want (%q, %q)", c.argv, op, p, c.op, c.path)
		}
	}
}

func TestWorkDirs(t *testing.T) {
	home, _ := os.UserHomeDir()
	got := workDirs("cd ~/worktrees/a && npm i; git -C /w/b status | tail; echo cd /w/c", "/r")
	want := []string{home + "/worktrees/a", "/w/b"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
	// a path inside a heredoc body, or only printed: not worked in
	if d := workDirs("cat > f.ts <<'EOF'\ncd ~/worktrees/x && npm ci\nEOF\ngrep worktrees/y z", "/r"); len(d) != 0 {
		t.Fatalf("heredoc/grep counted: %v", d)
	}
	if d := workDirs("cd sub", "/r"); len(d) != 1 || d[0] != "/r/sub" {
		t.Fatalf("relative cd: %v", d)
	}
}

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t",
		"GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_GLOBAL=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
}

func latest(t *testing.T, st *store.Store, kind string) map[string]map[string]any {
	t.Helper()
	recs, err := st.Latest(kind, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, r := range recs {
		var m map[string]any
		_ = json.Unmarshal(r.Data, &m)
		out[r.Key] = m
	}
	return out
}

func TestScanAttributesAndRemoves(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	d, _ := filepath.EvalSymlinks(t.TempDir())
	repo := filepath.Join(d, "repo")
	write(t, filepath.Join(repo, "README"), 10)
	run(t, repo, "git", "init", "-q", "-b", "main")
	run(t, repo, "git", "add", ".")
	run(t, repo, "git", "commit", "-qm", "init")
	wt := filepath.Join(d, "worktrees", "repo-feat")
	run(t, repo, "git", "worktree", "add", "-q", "-b", "feat", wt)
	write(t, filepath.Join(wt, "build", "out.bin"), 2<<20)

	sid := "11111111-2222-3333-4444-555555555555"
	scratch := filepath.Join(d, "tmp", "claude-1000")
	write(t, filepath.Join(scratch, "-repo", sid, "scratchpad", "dl", "data"), 3<<20)
	emptySid := "99999999-2222-3333-4444-555555555555"
	if err := os.MkdirAll(filepath.Join(scratch, "-repo", emptySid, "scratchpad"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(d, "claude")
	write(t, filepath.Join(cfg, "projects", "-repo", sid+".jsonl"), 5000)
	write(t, filepath.Join(cfg, "projects", "-repo", sid, "subagents", "agent-a.jsonl"), 9000)

	st, err := store.Open(filepath.Join(d, "probe.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	t.Setenv("CLAUDE_PROBE_STATE_DIR", filepath.Join(d, "state"))
	sc := New(st)
	sc.ScratchRoots = []string{scratch}
	sc.ConfigDirs = []string{cfg}
	sc.Touch(sid, repo, "", "", false)
	// the call that made the worktree, as the probe hands it over
	sc.afterCall(&callDone{sid: sid, tid: "toolu_1", cwd: repo, command: "git worktree add -b feat " + wt,
		added: []string{wt}})
	other := "77777777-2222-3333-4444-555555555555"
	sc.pass(true)

	items := latest(t, st, "storage")
	sp := items[filepath.Join(scratch, "-repo", sid)]
	if sp == nil || sp["kind"] != "scratchpad" || sp["sessionId"] != sid {
		t.Fatalf("scratchpad item: %v (all: %v)", sp, keys(items))
	}
	if _, ok := items[filepath.Join(scratch, "-repo", emptySid)]; ok {
		t.Fatal("an empty session dir is not an item")
	}
	w := items[wt]
	if w == nil || w["kind"] != "worktree" {
		t.Fatalf("worktree item missing: %v", keys(items))
	}
	if cb, _ := w["createdBy"].(map[string]any); cb == nil || cb["toolUseId"] != "toolu_1" {
		t.Fatalf("createdBy: %v", w["createdBy"])
	}
	g, _ := w["git"].(map[string]any)
	if g == nil || g["branch"] != "feat" || g["merged"] != true || g["dirty"].(float64) != 1 {
		t.Fatalf("git: %v", g)
	}
	// a session that cd's into it worked in it; one that only prints the path didn't
	sc.afterCall(&callDone{sid: other, tid: "toolu_o", cwd: "/", command: "cd " + wt + " && make"})
	sc.afterCall(&callDone{sid: "88888888-2222-3333-4444-555555555555", tid: "toolu_e", cwd: "/", command: "echo " + wt})
	sc.pass(true)
	ss := fmt.Sprint(latest(t, st, "storage")[wt]["sessions"])
	if !strings.Contains(ss, other) || strings.Contains(ss, "88888888") {
		t.Fatalf("sessions: %s", ss)
	}
	tr := items[filepath.Join(cfg, "projects", "-repo", sid)]
	if tr == nil || tr["kind"] != "transcript" {
		t.Fatalf("transcript item missing: %v", keys(items))
	}
	disks := latest(t, st, "disk")
	if len(disks) == 0 {
		t.Fatal("no disk record")
	}
	for _, dk := range disks {
		if dk["emptyScratch"] == nil {
			t.Fatalf("disk: %v", dk)
		}
	}

	// a call that wrote into the scratchpad: its growth is pinned on it
	write(t, filepath.Join(scratch, "-repo", sid, "scratchpad", "more"), 4<<20)
	sc.afterCall(&callDone{sid: sid, tid: "toolu_2", command: "make data"})
	grow := latest(t, st, "grow")["toolu_2"]
	if grow == nil {
		t.Fatal("no grow record for the call that wrote 4 MB")
	}

	// dirty + its session active: kept
	QuietFor = time.Hour
	if _, err := sc.Remove(wt, false, false); err == nil {
		t.Fatal("removed a worktree with uncommitted changes")
	}
	os.RemoveAll(filepath.Join(wt, "build"))
	if _, err := sc.Remove(wt, false, false); err == nil {
		t.Fatal("removed a worktree its session just used")
	}
	QuietFor = 0
	r, err := sc.Remove(wt, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(wt); !os.IsNotExist(err) {
		t.Fatal("worktree still there")
	}
	if !strings.Contains(r.Note, "deleted") {
		t.Fatalf("merged branch should go: %+v", r)
	}
	if latest(t, st, "storage")[wt]["gone"] != true {
		t.Fatal("no gone record")
	}
	// the scratch dir
	if _, err := sc.Remove(filepath.Join(scratch, "-repo", sid), false, false); err != nil {
		t.Fatal(err)
	}
	// never something else
	if _, err := sc.Remove(repo, true, false); err == nil {
		t.Fatal("removed the main working tree")
	}
	if _, err := sc.Remove(filepath.Join(cfg, "projects"), true, false); err == nil {
		t.Fatal("removed a non-item")
	}
}

func keys(m map[string]map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
