package shellsplit

import (
	"reflect"
	"testing"
)

func progs(parts []Part) []string {
	var out []string
	for _, p := range parts {
		if p.Program == nil {
			out = append(out, "")
		} else {
			out = append(out, *p.Program)
		}
	}
	return out
}

func TestPartsAndOperators(t *testing.T) {
	parts := Split("cd /x && npm run build 2>&1 | tail -20; echo done")
	var texts, opsGot []string
	for _, p := range parts {
		texts = append(texts, p.Text)
		if p.Op == nil {
			opsGot = append(opsGot, "")
		} else {
			opsGot = append(opsGot, *p.Op)
		}
	}
	if !reflect.DeepEqual(texts, []string{"cd /x", "npm run build 2>&1", "tail -20", "echo done"}) {
		t.Fatal(texts)
	}
	if !reflect.DeepEqual(opsGot, []string{"&&", "|", ";", ""}) {
		t.Fatal(opsGot)
	}
	if !reflect.DeepEqual(progs(parts), []string{"", "npm", "tail", ""}) {
		t.Fatal(progs(parts))
	}
}

func TestQuotesHeredocsRedirectionsSubshells(t *testing.T) {
	if n := len(Split(`echo "a && b | c"`)); n != 1 {
		t.Fatal(n)
	}
	if got := progs(Split("python3 - <<'EOF'\nx && y | z\nEOF\nls")); !reflect.DeepEqual(got, []string{"python3", "ls"}) {
		t.Fatal(got)
	}
	bg := Split("vite --port 5000 > /tmp/log 2>&1 &")
	if !bg[0].Background || *bg[0].Program != "vite" {
		t.Fatal(bg)
	}
	sub := Split("(cd a; make -j4) | tee log")
	if got := progs(sub); !reflect.DeepEqual(got, []string{"", "make", "tee"}) || sub[1].Depth != 1 || sub[2].Depth != 0 {
		t.Fatal(got, sub)
	}
	if p := Split("FOO=1 rtk git status"); *p[0].Program != "git" {
		t.Fatal(p)
	}
	if p := Split("timeout 30 npx vitest run"); *p[0].Program != "vitest" {
		t.Fatal(p)
	}
	if p := Split("for f in *.py; do wc -l $f; done"); p[0].Program != nil {
		t.Fatal(p)
	}
}

func code(c int) *int { return &c }

func TestProcessesGoUnderTheirPart(t *testing.T) {
	ps := []*Proc{
		{Pid: 10, Ppid: 1, Depth: 0, Label: "npm run build", StartedAt: 1000, EndedAt: 1005, CPUOwn: 0.01},
		{Pid: 11, Ppid: 10, Depth: 1, Label: "npm run build", StartedAt: 1000.1, EndedAt: 1004.9, CPUOwn: 0.4, ExitCode: code(0)},
		{Pid: 12, Ppid: 11, Depth: 2, Label: "vite", StartedAt: 1000.3, EndedAt: 1004.8, CPUOwn: 9.5, PeakRss: 900 << 20},
		{Pid: 13, Ppid: 10, Depth: 1, Label: "tail", StartedAt: 1000.1, EndedAt: 1004.95, CPUOwn: 0.01},
	}
	c := Components("cd /x && npm run build 2>&1 | tail -20; echo done", ps)
	if !c[0].Builtin || !reflect.DeepEqual(c[1].Pids, []int{11, 12}) || c[1].PeakRss != 900<<20 {
		t.Fatal(c)
	}
	if c[1].CPU < 9.89 || c[1].CPU > 9.91 || !reflect.DeepEqual(c[2].Pids, []int{13}) || !c[3].Builtin {
		t.Fatal(c)
	}
}

func TestWrappedProgramTakesItsPart(t *testing.T) {
	ps := []*Proc{
		{Pid: 10, Ppid: 1, Depth: 0, Label: "bash", StartedAt: 1000},
		{Pid: 20, Ppid: 10, Depth: 1, Label: "grep", StartedAt: 1000.1},
		{Pid: 21, Ppid: 10, Depth: 1, Label: "head", StartedAt: 1000.1},
		{Pid: 30, Ppid: 10, Depth: 1, Label: "npm exec tsc", Argv: "npm exec tsc --noEmit", StartedAt: 1001, CPUOwn: 0.5},
		{Pid: 31, Ppid: 30, Depth: 2, Label: "tsc", StartedAt: 1001.2, CPUOwn: 50},
		{Pid: 32, Ppid: 10, Depth: 1, Label: "grep", StartedAt: 1001},
		{Pid: 33, Ppid: 10, Depth: 1, Label: "head", StartedAt: 1001},
	}
	c := Components("grep x f | head; cd .. && npx tsc --noEmit 2>&1 | grep error | head", ps)
	for _, p := range c {
		if p.Text == "npx tsc --noEmit 2>&1" && !reflect.DeepEqual(p.Pids, []int{30, 31}) {
			t.Fatal(p)
		}
		if p.Text == "head" && p.CPU > 1 {
			t.Fatal("tsc's CPU landed on head", p)
		}
	}
}

func TestUnnamedProcessJoinsTheRunningPart(t *testing.T) {
	ps := []*Proc{
		{Pid: 10, Ppid: 1, Depth: 0, Label: "bash", StartedAt: 1000},
		{Pid: 20, Ppid: 10, Depth: 1, Label: "ls", StartedAt: 1000.1, ExitCode: code(2)},
		{Pid: 21, Ppid: 10, Depth: 1, Label: "mystery", StartedAt: 1000.5, ExitCode: code(0)},
	}
	c := Components("ls /nope; echo after", ps)
	if *c[0].ExitCode != 2 || !reflect.DeepEqual(c[0].Pids, []int{20, 21}) {
		t.Fatal(c)
	}
}

func TestLabels(t *testing.T) {
	cases := map[string]string{"npm run build 2>&1": "npm run build", "git push origin HEAD": "git push",
		"tail -20": "tail"}
	for text, want := range cases {
		p := Split(text)[0]
		if got := Label(p); got != want {
			t.Fatalf("%q → %q, want %q", text, got, want)
		}
	}
}
