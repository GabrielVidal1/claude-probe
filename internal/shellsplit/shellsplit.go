// Package shellsplit splits a shell command line into the parts it runs and
// puts each process a call started under the part it belongs to.
//
// What the command says — `cd x && npm run build 2>&1 | tail -20; vite &` is
// four parts joined by &&, |, ; and a trailing & — is read with a small
// tokenizer (quotes, \ escapes, $( … ) / backticks and heredoc bodies stay
// inside their word or part). What ran is the probe's process tree: the
// shell's direct children are the parts that weren't builtins, and everything
// under a child (npm → node → esbuild) belongs to that part. The two are
// joined in order: each child takes the next part whose program it is
// (wrappers like rtk, timeout, npx seen through); a process no part names
// (a subshell's fork, a $( … )) joins the part that was running then.
package shellsplit

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var ops = []string{"&&", "||", ";;", "|&", ";", "|", "&", "\n"}

// Builtins and keywords: a part made of these forks nothing.
var builtins = set("cd", "export", "source", ".", "set", "shopt", "unset", "local", "pushd",
	"popd", "true", "false", "echo", "printf", "test", "[", "[[", "read", "return", "exit",
	"trap", "wait", "eval", "exec", "alias", "unalias", "type", "command", "builtin",
	"declare", "typeset", "let", ":", "shift", "umask", "ulimit", "hash", "jobs", "fg", "bg",
	"kill", "times", "getopts")
var keywords = set("if", "then", "elif", "else", "fi", "for", "while", "until", "do", "done",
	"case", "esac", "in", "function", "select", "!", "{", "}", "(", ")", "time")
var wrappers = set("env", "nohup", "setsid", "timeout", "xvfb-run", "rtk", "time", "nice",
	"flock", "stdbuf", "sudo", "uvx", "npx", "command", "exec", "builtin")

var (
	assignRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=`)
	heredocRE = regexp.MustCompile(`<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)['"]?`)
	redirRE   = regexp.MustCompile(`^\d*[<>]`)
	redirTgt  = regexp.MustCompile(`[<>]&?\S+$`)
	durRE     = regexp.MustCompile(`^[\d.]+[smhd]?$`)
)

const maxParts = 40

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Part is one part of a command line and what it ran.
type Part struct {
	Text       string   `json:"text"`
	Program    *string  `json:"program"`
	Op         *string  `json:"op"`
	Background bool     `json:"background"`
	Depth      int      `json:"depth"`
	Builtin    bool     `json:"builtin"`
	Other      bool     `json:"other,omitempty"`
	Pids       []int    `json:"pids"`
	CPU        float64  `json:"cpu"`
	PeakRss    int64    `json:"peakRss"`
	ExitCode   *int     `json:"exitCode"`
	StartedAt  *float64 `json:"startedAt"`
	EndedAt    *float64 `json:"endedAt"`
	top        *Proc
}

// Proc is what the mapping needs of a process.
type Proc struct {
	Pid       int
	Ppid      int
	Depth     int
	Label     string
	Argv      string
	StartedAt float64
	EndedAt   float64 // 0 while it runs
	CPUOwn    float64
	PeakRss   int64
	ExitCode  *int
	Signal    *int
}

func stripHeredocs(cmd string) string {
	lines := strings.Split(cmd, "\n")
	var out []string
	for i := 0; i < len(lines); {
		line := lines[i]
		out = append(out, line)
		i++
		for _, m := range heredocRE.FindAllStringSubmatch(line, -1) {
			tag := m[2]
			for i < len(lines) && strings.TrimSpace(lines[i]) != tag {
				i++
			}
			i++
		}
	}
	return strings.Join(out, "\n")
}

type token struct{ kind, text string } // kind: w (word), op, ( or )

func tokens(cmd string) []token {
	var out []token
	var word strings.Builder
	flush := func() {
		if word.Len() > 0 {
			out = append(out, token{"w", word.String()})
			word.Reset()
		}
	}
	rs := []rune(cmd)
	n := len(rs)
	for i := 0; i < n; {
		c := rs[i]
		switch {
		case c == '\\' && i+1 < n:
			word.WriteString(string(rs[i : i+2]))
			i += 2
		case c == '\'' || c == '"' || c == '`':
			j := i + 1
			for j < n && rs[j] != c {
				if c != '\'' && rs[j] == '\\' {
					j += 2
				} else {
					j++
				}
			}
			end := j + 1
			if end > n {
				end = n
			}
			word.WriteString(string(rs[i:end]))
			i = j + 1
		case c == '$' && i+1 < n && rs[i+1] == '(':
			depth, j := 0, i+1
			for j < n {
				if rs[j] == '(' {
					depth++
				} else if rs[j] == ')' {
					depth--
					if depth == 0 {
						break
					}
				} else if rs[j] == '\'' || rs[j] == '"' {
					q := rs[j]
					j++
					for j < n && rs[j] != q {
						j++
					}
				}
				j++
			}
			end := j + 1
			if end > n {
				end = n
			}
			word.WriteString(string(rs[i:end]))
			i = j + 1
		case c == '#' && word.Len() == 0: // a comment, to the end of the line
			for i < n && rs[i] != '\n' {
				i++
			}
		case c == ' ' || c == '\t':
			flush()
			i++
		case c == ')' || (c == '(' && word.Len() == 0):
			flush()
			out = append(out, token{string(c), string(c)})
			i++
		default:
			rest := string(rs[i:])
			op := ""
			for _, o := range ops {
				if strings.HasPrefix(rest, o) {
					op = o
					break
				}
			}
			// `2>&1`, `&>`, `>&`: a redirection, not the background operator
			if (op == "&" || op == "|&") && (strings.HasPrefix(rest, "&>") ||
				(word.Len() > 0 && strings.HasSuffix(word.String(), ">"))) {
				op = ""
			}
			if op != "" {
				flush()
				out = append(out, token{"op", op})
				i += len([]rune(op))
			} else {
				word.WriteRune(c)
				i++
			}
		}
	}
	flush()
	return out
}

func base(w string) string { return filepath.Base(strings.Trim(w, `'"`)) }

// Program is the program a simple command runs (assignments, keywords,
// redirections and wrappers skipped) — "" for a builtin-only part.
func Program(words []string) string {
	var ws []string
	for _, w := range words {
		if !assignRE.MatchString(w) {
			ws = append(ws, w)
		}
	}
	if len(ws) > 0 && (ws[0] == "for" || ws[0] == "select" || ws[0] == "case") {
		return "" // a loop header
	}
	for i := 0; i < len(ws); {
		w := ws[i]
		if keywords[w] {
			i++
			continue
		}
		if redirRE.MatchString(w) { // a redirection; its target next
			if redirTgt.MatchString(w) && !strings.HasSuffix(w, ">") && !strings.HasSuffix(w, "<") {
				i++
			} else {
				i += 2
			}
			continue
		}
		b := base(w)
		if wrappers[b] {
			i++
			for i < len(ws) && (strings.HasPrefix(ws[i], "-") || assignRE.MatchString(ws[i]) || durRE.MatchString(ws[i])) {
				i++
			}
			if b == "rtk" && i < len(ws) && ws[i] == "proxy" {
				i++
			}
			continue
		}
		if builtins[b] {
			return ""
		}
		return b
	}
	return ""
}

func ptr[T any](v T) *T { return &v }

// Split returns the command's parts in order.
func Split(command string) []Part {
	toks := tokens(stripHeredocs(command))
	var parts []Part
	var words []string
	depth := 0
	closePart := func(op string) {
		if len(words) > 0 {
			text := strings.Join(words, " ")
			if len(text) > 300 {
				text = text[:300]
			}
			p := Part{Text: text, Depth: depth, Pids: []int{}}
			if prog := Program(words); prog != "" {
				p.Program = ptr(prog)
			}
			if op != "" {
				p.Op = ptr(op)
				p.Background = op == "&"
			}
			parts = append(parts, p)
			words = nil
		} else if op != "" && len(parts) > 0 && parts[len(parts)-1].Op == nil {
			parts[len(parts)-1].Op = ptr(op)
			parts[len(parts)-1].Background = op == "&"
		}
	}
	for _, t := range toks {
		switch t.kind {
		case "w":
			words = append(words, t.text)
		case "(":
			closePart("")
			depth++
		case ")":
			closePart("")
			if depth > 0 {
				depth--
			}
		default:
			if t.text == "\n" {
				closePart("")
			} else {
				closePart(t.text)
			}
		}
		if len(parts) >= maxParts {
			break
		}
	}
	closePart("")
	return parts
}

// Matches says whether proc is the part's program: its label or command
// line names it among their first words (`npx tsc` runs as `npm exec tsc`).
func Matches(prog *string, p *Proc) bool {
	if prog == nil || *prog == "" {
		return false
	}
	words := strings.Fields(p.Label + " " + p.Argv)
	if len(words) > 8 {
		words = words[:8]
	}
	for _, w := range words {
		b := base(w)
		if b == *prog || (len(*prog) >= 3 && strings.HasPrefix(b, *prog)) {
			return true
		}
	}
	return false
}

// Components returns the call's parts with the processes each one ran (its
// subtree, in start order) and their sums; processes no part takes are a
// last part flagged Other.
func Components(command string, procs []*Proc) []Part {
	parts := Split(command)
	if len(procs) == 0 {
		for i := range parts {
			parts[i].Builtin = parts[i].Program == nil
		}
		return parts
	}
	byPid := map[int]*Proc{}
	for _, p := range procs {
		byPid[p.Pid] = p
	}
	shell := procs[0]
	for _, p := range procs {
		if p.Depth < shell.Depth || (p.Depth == shell.Depth && p.StartedAt < shell.StartedAt) {
			shell = p
		}
	}
	kids := map[int][]*Proc{}
	var tops []*Proc
	for _, p := range procs {
		if p == shell {
			continue
		}
		kids[p.Ppid] = append(kids[p.Ppid], p)
		if _, ok := byPid[p.Ppid]; p.Ppid == shell.Pid || !ok {
			tops = append(tops, p)
		}
	}
	sort.SliceStable(tops, func(i, j int) bool { return tops[i].StartedAt < tops[j].StartedAt })
	owner := map[int]int{}
	cursor := 0
	for _, top := range tops {
		idx := -1
		for i := cursor; i < len(parts); i++ {
			if Matches(parts[i].Program, top) {
				idx = i
				break
			}
		}
		if idx < 0 { // a forked subshell, $( … ): the part running then
			if len(parts) == 0 {
				continue
			}
			idx = 0
			if cursor > 0 {
				idx = cursor - 1
			}
			if !Matches(parts[idx].Program, top) {
				// a subshell's fork carries the shell's argv: its first
				// descendant with a program of its own names it
			outer:
				for _, d := range kids[top.Pid] {
					for i := cursor; i < len(parts); i++ {
						if Matches(parts[i].Program, d) {
							idx = i
							break outer
						}
					}
				}
			}
		} else {
			cursor = idx + 1
			parts[idx].top = top
		}
		stack := []*Proc{top}
		for len(stack) > 0 {
			p := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			owner[p.Pid] = idx
			stack = append(stack, kids[p.Pid]...)
		}
	}
	other := Part{Other: true, Pids: []int{}}
	ordered := append([]*Proc(nil), procs...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].StartedAt < ordered[j].StartedAt })
	for _, p := range ordered {
		if p == shell {
			continue
		}
		part := &other
		if i, ok := owner[p.Pid]; ok {
			part = &parts[i]
		}
		part.Pids = append(part.Pids, p.Pid)
		part.CPU += p.CPUOwn
		if p.PeakRss > part.PeakRss {
			part.PeakRss = p.PeakRss
		}
		if part.StartedAt == nil || p.StartedAt < *part.StartedAt {
			part.StartedAt = ptr(p.StartedAt)
		}
		if p.EndedAt > 0 && (part.EndedAt == nil || p.EndedAt > *part.EndedAt) {
			part.EndedAt = ptr(p.EndedAt)
		}
	}
	for i := range parts {
		if t := parts[i].top; t != nil {
			if t.ExitCode != nil {
				parts[i].ExitCode = ptr(*t.ExitCode)
			} else if t.Signal != nil {
				parts[i].ExitCode = ptr(128 + *t.Signal) // the shell's own convention
			}
		}
		parts[i].Builtin = parts[i].Program == nil && len(parts[i].Pids) == 0
	}
	if len(other.Pids) > 0 {
		parts = append(parts, other)
	}
	return parts
}

// Label is a part's name in the rankings: its program, plus the subcommand
// for the programs whose subcommand is the point (npm run build, git push).
func Label(p Part) string {
	if p.Other {
		return "(other)"
	}
	if p.Program == nil {
		f := strings.Fields(p.Text)
		if len(f) == 0 {
			return "bash"
		}
		return f[0]
	}
	prog := *p.Program
	keep := map[string]int{"npm": 2, "pnpm": 2, "yarn": 2, "bun": 2, "uv": 2, "git": 1,
		"docker": 1, "cargo": 1, "go": 1, "make": 1, "python3": 1, "python": 1, "node": 1,
		"kubectl": 1, "gh": 2, "npx": 1, "uvx": 1, "systemctl": 1}[prog]
	words := strings.Fields(p.Text)
	i := 0
	for k, w := range words {
		if w == prog || strings.HasSuffix(w, "/"+prog) {
			i = k
			break
		}
	}
	out := []string{prog}
	for _, w := range words[min(i+1, len(words)):min(i+1+keep, len(words))] {
		if strings.HasPrefix(w, "-") || len(w) >= 30 || strings.ContainsAny(w, "/<>|&;$'\"=") {
			continue
		}
		out = append(out, w)
	}
	s := strings.Join(out, " ")
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}
